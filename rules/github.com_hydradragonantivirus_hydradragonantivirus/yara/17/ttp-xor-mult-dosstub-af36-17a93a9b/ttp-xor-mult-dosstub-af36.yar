rule TTP_XOR_MULT_DOSStub_af36 {
  strings:
    $key_af36 = { fb 5e [2] 8f 46 [2] c8 44 [2] 8f 55 [2] c1 59 [2] cd 53 [2] da 58 [2] c1 16 [2] fc }

  condition:
    any of them
}