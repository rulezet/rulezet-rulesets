rule TTP_XOR_MULT_DOSStub_afe1 {
  strings:
    $key_afe1 = { fb 89 [2] 8f 91 [2] c8 93 [2] 8f 82 [2] c1 8e [2] cd 84 [2] da 8f [2] c1 c1 [2] fc }

  condition:
    any of them
}