rule TTP_XOR_MULT_DOSStub_78a0 {
  strings:
    $key_78a0 = { 2c c8 [2] 58 d0 [2] 1f d2 [2] 58 c3 [2] 16 cf [2] 1a c5 [2] 0d ce [2] 16 80 [2] 2b }

  condition:
    any of them
}