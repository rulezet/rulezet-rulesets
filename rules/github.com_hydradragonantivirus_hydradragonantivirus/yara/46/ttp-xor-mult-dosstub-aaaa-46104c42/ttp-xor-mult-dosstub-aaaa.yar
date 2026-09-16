rule TTP_XOR_MULT_DOSStub_aaaa {
  strings:
    $key_aaaa = { fe c2 [2] 8a da [2] cd d8 [2] 8a c9 [2] c4 c5 [2] c8 cf [2] df c4 [2] c4 8a [2] f9 }

  condition:
    any of them
}