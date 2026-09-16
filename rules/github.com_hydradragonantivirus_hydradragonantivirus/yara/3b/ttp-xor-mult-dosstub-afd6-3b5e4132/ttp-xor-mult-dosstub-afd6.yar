rule TTP_XOR_MULT_DOSStub_afd6 {
  strings:
    $key_afd6 = { fb be [2] 8f a6 [2] c8 a4 [2] 8f b5 [2] c1 b9 [2] cd b3 [2] da b8 [2] c1 f6 [2] fc }

  condition:
    any of them
}