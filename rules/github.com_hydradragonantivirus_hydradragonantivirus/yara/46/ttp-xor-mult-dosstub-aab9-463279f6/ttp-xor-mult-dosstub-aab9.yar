rule TTP_XOR_MULT_DOSStub_aab9 {
  strings:
    $key_aab9 = { fe d1 [2] 8a c9 [2] cd cb [2] 8a da [2] c4 d6 [2] c8 dc [2] df d7 [2] c4 99 [2] f9 }

  condition:
    any of them
}