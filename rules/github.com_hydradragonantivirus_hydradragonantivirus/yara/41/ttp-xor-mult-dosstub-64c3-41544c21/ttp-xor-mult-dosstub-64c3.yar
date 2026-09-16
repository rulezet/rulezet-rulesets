rule TTP_XOR_MULT_DOSStub_64c3 {
  strings:
    $key_64c3 = { 30 ab [2] 44 b3 [2] 03 b1 [2] 44 a0 [2] 0a ac [2] 06 a6 [2] 11 ad [2] 0a e3 [2] 37 }

  condition:
    any of them
}