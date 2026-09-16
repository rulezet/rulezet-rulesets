rule TTP_XOR_MULT_DOSStub_af47 {
  strings:
    $key_af47 = { fb 2f [2] 8f 37 [2] c8 35 [2] 8f 24 [2] c1 28 [2] cd 22 [2] da 29 [2] c1 67 [2] fc }

  condition:
    any of them
}