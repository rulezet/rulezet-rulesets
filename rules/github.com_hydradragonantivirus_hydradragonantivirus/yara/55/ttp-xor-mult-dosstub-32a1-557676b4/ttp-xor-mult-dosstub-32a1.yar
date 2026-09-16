rule TTP_XOR_MULT_DOSStub_32a1 {
  strings:
    $key_32a1 = { 66 c9 [2] 12 d1 [2] 55 d3 [2] 12 c2 [2] 5c ce [2] 50 c4 [2] 47 cf [2] 5c 81 [2] 61 }

  condition:
    any of them
}