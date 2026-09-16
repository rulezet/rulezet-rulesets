rule TTP_XOR_MULT_DOSStub_afd2 {
  strings:
    $key_afd2 = { fb ba [2] 8f a2 [2] c8 a0 [2] 8f b1 [2] c1 bd [2] cd b7 [2] da bc [2] c1 f2 [2] fc }

  condition:
    any of them
}