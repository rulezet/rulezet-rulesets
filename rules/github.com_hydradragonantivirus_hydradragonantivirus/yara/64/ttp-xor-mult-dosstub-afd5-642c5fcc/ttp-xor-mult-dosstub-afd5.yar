rule TTP_XOR_MULT_DOSStub_afd5 {
  strings:
    $key_afd5 = { fb bd [2] 8f a5 [2] c8 a7 [2] 8f b6 [2] c1 ba [2] cd b0 [2] da bb [2] c1 f5 [2] fc }

  condition:
    any of them
}