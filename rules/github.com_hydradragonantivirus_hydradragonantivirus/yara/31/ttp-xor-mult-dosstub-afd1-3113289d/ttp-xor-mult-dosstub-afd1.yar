rule TTP_XOR_MULT_DOSStub_afd1 {
  strings:
    $key_afd1 = { fb b9 [2] 8f a1 [2] c8 a3 [2] 8f b2 [2] c1 be [2] cd b4 [2] da bf [2] c1 f1 [2] fc }

  condition:
    any of them
}