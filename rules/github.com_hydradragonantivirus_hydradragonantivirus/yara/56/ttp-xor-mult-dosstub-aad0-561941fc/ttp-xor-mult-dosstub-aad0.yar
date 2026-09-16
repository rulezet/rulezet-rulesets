rule TTP_XOR_MULT_DOSStub_aad0 {
  strings:
    $key_aad0 = { fe b8 [2] 8a a0 [2] cd a2 [2] 8a b3 [2] c4 bf [2] c8 b5 [2] df be [2] c4 f0 [2] f9 }

  condition:
    any of them
}