rule TTP_XOR_MULT_DOSStub_a1a1 {
  strings:
    $key_a1a1 = { f5 c9 [2] 81 d1 [2] c6 d3 [2] 81 c2 [2] cf ce [2] c3 c4 [2] d4 cf [2] cf 81 [2] f2 }

  condition:
    any of them
}