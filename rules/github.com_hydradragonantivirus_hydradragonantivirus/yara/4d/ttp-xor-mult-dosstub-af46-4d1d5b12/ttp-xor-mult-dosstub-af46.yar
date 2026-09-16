rule TTP_XOR_MULT_DOSStub_af46 {
  strings:
    $key_af46 = { fb 2e [2] 8f 36 [2] c8 34 [2] 8f 25 [2] c1 29 [2] cd 23 [2] da 28 [2] c1 66 [2] fc }

  condition:
    any of them
}