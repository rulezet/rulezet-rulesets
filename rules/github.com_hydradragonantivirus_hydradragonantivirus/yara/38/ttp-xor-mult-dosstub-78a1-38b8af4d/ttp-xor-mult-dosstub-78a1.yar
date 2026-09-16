rule TTP_XOR_MULT_DOSStub_78a1 {
  strings:
    $key_78a1 = { 2c c9 [2] 58 d1 [2] 1f d3 [2] 58 c2 [2] 16 ce [2] 1a c4 [2] 0d cf [2] 16 81 [2] 2b }

  condition:
    any of them
}