rule TTP_XOR_MULT_DOSStub_42a1 {
  strings:
    $key_42a1 = { 16 c9 [2] 62 d1 [2] 25 d3 [2] 62 c2 [2] 2c ce [2] 20 c4 [2] 37 cf [2] 2c 81 [2] 11 }

  condition:
    any of them
}