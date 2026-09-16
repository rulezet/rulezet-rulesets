rule TTP_XOR_MULT_DOSStub_a3a0 {
  strings:
    $key_a3a0 = { f7 c8 [2] 83 d0 [2] c4 d2 [2] 83 c3 [2] cd cf [2] c1 c5 [2] d6 ce [2] cd 80 [2] f0 }

  condition:
    any of them
}