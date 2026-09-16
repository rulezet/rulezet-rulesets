rule TTP_XOR_MULT_DOSStub_af50 {
  strings:
    $key_af50 = { fb 38 [2] 8f 20 [2] c8 22 [2] 8f 33 [2] c1 3f [2] cd 35 [2] da 3e [2] c1 70 [2] fc }

  condition:
    any of them
}