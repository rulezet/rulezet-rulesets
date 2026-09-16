rule TTP_XOR_MULT_DOSStub_aad5 {
  strings:
    $key_aad5 = { fe bd [2] 8a a5 [2] cd a7 [2] 8a b6 [2] c4 ba [2] c8 b0 [2] df bb [2] c4 f5 [2] f9 }

  condition:
    any of them
}