rule TTP_XOR_MULT_DOSStub_65c8 {
  strings:
    $key_65c8 = { 31 a0 [2] 45 b8 [2] 02 ba [2] 45 ab [2] 0b a7 [2] 07 ad [2] 10 a6 [2] 0b e8 [2] 36 }

  condition:
    any of them
}