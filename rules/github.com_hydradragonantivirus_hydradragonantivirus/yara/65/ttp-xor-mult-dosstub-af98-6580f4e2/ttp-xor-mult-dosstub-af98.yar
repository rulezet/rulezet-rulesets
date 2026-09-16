rule TTP_XOR_MULT_DOSStub_af98 {
  strings:
    $key_af98 = { fb f0 [2] 8f e8 [2] c8 ea [2] 8f fb [2] c1 f7 [2] cd fd [2] da f6 [2] c1 b8 [2] fc }

  condition:
    any of them
}