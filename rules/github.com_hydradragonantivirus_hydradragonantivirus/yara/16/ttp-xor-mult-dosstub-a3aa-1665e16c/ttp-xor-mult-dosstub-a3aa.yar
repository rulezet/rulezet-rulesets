rule TTP_XOR_MULT_DOSStub_a3aa {
  strings:
    $key_a3aa = { f7 c2 [2] 83 da [2] c4 d8 [2] 83 c9 [2] cd c5 [2] c1 cf [2] d6 c4 [2] cd 8a [2] f0 }

  condition:
    any of them
}