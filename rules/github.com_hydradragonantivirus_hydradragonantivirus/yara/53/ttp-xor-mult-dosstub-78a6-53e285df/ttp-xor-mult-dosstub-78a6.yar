rule TTP_XOR_MULT_DOSStub_78a6 {
  strings:
    $key_78a6 = { 2c ce [2] 58 d6 [2] 1f d4 [2] 58 c5 [2] 16 c9 [2] 1a c3 [2] 0d c8 [2] 16 86 [2] 2b }

  condition:
    any of them
}