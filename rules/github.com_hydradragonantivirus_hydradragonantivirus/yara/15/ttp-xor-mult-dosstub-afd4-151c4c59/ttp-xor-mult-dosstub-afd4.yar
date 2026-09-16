rule TTP_XOR_MULT_DOSStub_afd4 {
  strings:
    $key_afd4 = { fb bc [2] 8f a4 [2] c8 a6 [2] 8f b7 [2] c1 bb [2] cd b1 [2] da ba [2] c1 f4 [2] fc }

  condition:
    any of them
}