rule TTP_XOR_MULT_DOSStub_a3ac {
  strings:
    $key_a3ac = { f7 c4 [2] 83 dc [2] c4 de [2] 83 cf [2] cd c3 [2] c1 c9 [2] d6 c2 [2] cd 8c [2] f0 }

  condition:
    any of them
}