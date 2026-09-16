rule TTP_XOR_MULT_DOSStub_aff6 {
  strings:
    $key_aff6 = { fb 9e [2] 8f 86 [2] c8 84 [2] 8f 95 [2] c1 99 [2] cd 93 [2] da 98 [2] c1 d6 [2] fc }

  condition:
    any of them
}