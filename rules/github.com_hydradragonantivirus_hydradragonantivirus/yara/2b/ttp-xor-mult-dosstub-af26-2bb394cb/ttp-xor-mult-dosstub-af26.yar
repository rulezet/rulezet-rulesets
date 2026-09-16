rule TTP_XOR_MULT_DOSStub_af26 {
  strings:
    $key_af26 = { fb 4e [2] 8f 56 [2] c8 54 [2] 8f 45 [2] c1 49 [2] cd 43 [2] da 48 [2] c1 06 [2] fc }

  condition:
    any of them
}