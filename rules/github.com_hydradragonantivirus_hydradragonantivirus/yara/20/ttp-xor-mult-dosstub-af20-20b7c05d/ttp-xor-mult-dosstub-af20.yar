rule TTP_XOR_MULT_DOSStub_af20 {
  strings:
    $key_af20 = { fb 48 [2] 8f 50 [2] c8 52 [2] 8f 43 [2] c1 4f [2] cd 45 [2] da 4e [2] c1 00 [2] fc }

  condition:
    any of them
}