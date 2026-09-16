rule TTP_XOR_MULT_DOSStub_59a1 {
  strings:
    $key_59a1 = { 0d c9 [2] 79 d1 [2] 3e d3 [2] 79 c2 [2] 37 ce [2] 3b c4 [2] 2c cf [2] 37 81 [2] 0a }

  condition:
    any of them
}