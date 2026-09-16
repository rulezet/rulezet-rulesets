rule TTP_XOR_MULT_DOSStub_af41 {
  strings:
    $key_af41 = { fb 29 [2] 8f 31 [2] c8 33 [2] 8f 22 [2] c1 2e [2] cd 24 [2] da 2f [2] c1 61 [2] fc }

  condition:
    any of them
}