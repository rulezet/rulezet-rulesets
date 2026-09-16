rule TTP_XOR_MULT_DOSStub_a3a7 {
  strings:
    $key_a3a7 = { f7 cf [2] 83 d7 [2] c4 d5 [2] 83 c4 [2] cd c8 [2] c1 c2 [2] d6 c9 [2] cd 87 [2] f0 }

  condition:
    any of them
}