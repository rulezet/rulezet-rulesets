rule TTP_XOR_MULT_DOSStub_affb {
  strings:
    $key_affb = { fb 93 [2] 8f 8b [2] c8 89 [2] 8f 98 [2] c1 94 [2] cd 9e [2] da 95 [2] c1 db [2] fc }

  condition:
    any of them
}