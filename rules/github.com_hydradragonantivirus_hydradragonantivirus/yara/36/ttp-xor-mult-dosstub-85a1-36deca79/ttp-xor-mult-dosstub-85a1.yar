rule TTP_XOR_MULT_DOSStub_85a1 {
  strings:
    $key_85a1 = { d1 c9 [2] a5 d1 [2] e2 d3 [2] a5 c2 [2] eb ce [2] e7 c4 [2] f0 cf [2] eb 81 [2] d6 }

  condition:
    any of them
}