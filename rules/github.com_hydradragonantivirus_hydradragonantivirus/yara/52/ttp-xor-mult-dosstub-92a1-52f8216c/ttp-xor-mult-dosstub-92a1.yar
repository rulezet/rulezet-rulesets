rule TTP_XOR_MULT_DOSStub_92a1 {
  strings:
    $key_92a1 = { c6 c9 [2] b2 d1 [2] f5 d3 [2] b2 c2 [2] fc ce [2] f0 c4 [2] e7 cf [2] fc 81 [2] c1 }

  condition:
    any of them
}