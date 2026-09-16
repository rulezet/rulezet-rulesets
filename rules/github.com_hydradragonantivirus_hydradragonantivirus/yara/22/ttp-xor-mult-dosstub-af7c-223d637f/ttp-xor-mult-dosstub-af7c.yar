rule TTP_XOR_MULT_DOSStub_af7c {
  strings:
    $key_af7c = { fb 14 [2] 8f 0c [2] c8 0e [2] 8f 1f [2] c1 13 [2] cd 19 [2] da 12 [2] c1 5c [2] fc }

  condition:
    any of them
}