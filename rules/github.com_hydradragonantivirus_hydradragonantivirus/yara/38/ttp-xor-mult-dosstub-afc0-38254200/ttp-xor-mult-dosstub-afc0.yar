rule TTP_XOR_MULT_DOSStub_afc0 {
  strings:
    $key_afc0 = { fb a8 [2] 8f b0 [2] c8 b2 [2] 8f a3 [2] c1 af [2] cd a5 [2] da ae [2] c1 e0 [2] fc }

  condition:
    any of them
}