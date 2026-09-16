rule TTP_XOR_MULT_DOSStub_54c8 {
  strings:
    $key_54c8 = { 00 a0 [2] 74 b8 [2] 33 ba [2] 74 ab [2] 3a a7 [2] 36 ad [2] 21 a6 [2] 3a e8 [2] 07 }

  condition:
    any of them
}