rule TTP_XOR_MULT_DOSStub_af99 {
  strings:
    $key_af99 = { fb f1 [2] 8f e9 [2] c8 eb [2] 8f fa [2] c1 f6 [2] cd fc [2] da f7 [2] c1 b9 [2] fc }

  condition:
    any of them
}