rule TTP_XOR_MULT_DOSStub_95a1 {
  strings:
    $key_95a1 = { c1 c9 [2] b5 d1 [2] f2 d3 [2] b5 c2 [2] fb ce [2] f7 c4 [2] e0 cf [2] fb 81 [2] c6 }

  condition:
    any of them
}