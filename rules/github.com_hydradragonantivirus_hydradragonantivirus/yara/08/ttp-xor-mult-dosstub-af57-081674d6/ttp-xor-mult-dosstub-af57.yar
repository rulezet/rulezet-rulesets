rule TTP_XOR_MULT_DOSStub_af57 {
  strings:
    $key_af57 = { fb 3f [2] 8f 27 [2] c8 25 [2] 8f 34 [2] c1 38 [2] cd 32 [2] da 39 [2] c1 77 [2] fc }

  condition:
    any of them
}