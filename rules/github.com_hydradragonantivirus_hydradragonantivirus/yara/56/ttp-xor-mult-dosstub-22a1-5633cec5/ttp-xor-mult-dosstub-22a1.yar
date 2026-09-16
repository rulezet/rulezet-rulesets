rule TTP_XOR_MULT_DOSStub_22a1 {
  strings:
    $key_22a1 = { 76 c9 [2] 02 d1 [2] 45 d3 [2] 02 c2 [2] 4c ce [2] 40 c4 [2] 57 cf [2] 4c 81 [2] 71 }

  condition:
    any of them
}