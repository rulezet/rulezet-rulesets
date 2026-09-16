rule TTP_XOR_MULT_DOSStub_aaa0 {
  strings:
    $key_aaa0 = { fe c8 [2] 8a d0 [2] cd d2 [2] 8a c3 [2] c4 cf [2] c8 c5 [2] df ce [2] c4 80 [2] f9 }

  condition:
    any of them
}