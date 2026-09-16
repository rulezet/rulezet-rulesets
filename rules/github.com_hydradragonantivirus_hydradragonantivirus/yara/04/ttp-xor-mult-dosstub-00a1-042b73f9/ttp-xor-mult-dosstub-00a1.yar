rule TTP_XOR_MULT_DOSStub_00a1 {
  strings:
    $key_00a1 = { 54 c9 [2] 20 d1 [2] 67 d3 [2] 20 c2 [2] 6e ce [2] 62 c4 [2] 75 cf [2] 6e 81 [2] 53 }

  condition:
    any of them
}