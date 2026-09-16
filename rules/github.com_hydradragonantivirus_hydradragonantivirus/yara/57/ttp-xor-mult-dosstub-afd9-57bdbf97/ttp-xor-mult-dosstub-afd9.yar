rule TTP_XOR_MULT_DOSStub_afd9 {
  strings:
    $key_afd9 = { fb b1 [2] 8f a9 [2] c8 ab [2] 8f ba [2] c1 b6 [2] cd bc [2] da b7 [2] c1 f9 [2] fc }

  condition:
    any of them
}