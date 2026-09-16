rule TTP_XOR_MULT_DOSStub_aff0 {
  strings:
    $key_aff0 = { fb 98 [2] 8f 80 [2] c8 82 [2] 8f 93 [2] c1 9f [2] cd 95 [2] da 9e [2] c1 d0 [2] fc }

  condition:
    any of them
}