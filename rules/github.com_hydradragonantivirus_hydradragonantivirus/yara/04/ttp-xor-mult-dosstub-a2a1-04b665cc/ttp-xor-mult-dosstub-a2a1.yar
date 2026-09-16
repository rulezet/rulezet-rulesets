rule TTP_XOR_MULT_DOSStub_a2a1 {
  strings:
    $key_a2a1 = { f6 c9 [2] 82 d1 [2] c5 d3 [2] 82 c2 [2] cc ce [2] c0 c4 [2] d7 cf [2] cc 81 [2] f1 }

  condition:
    any of them
}