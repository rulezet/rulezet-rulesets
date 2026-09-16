rule TTP_XOR_MULT_DOSStub_64c8 {
  strings:
    $key_64c8 = { 30 a0 [2] 44 b8 [2] 03 ba [2] 44 ab [2] 0a a7 [2] 06 ad [2] 11 a6 [2] 0a e8 [2] 37 }

  condition:
    any of them
}