rule TTP_XOR_MULT_DOSStub_af7b {
  strings:
    $key_af7b = { fb 13 [2] 8f 0b [2] c8 09 [2] 8f 18 [2] c1 14 [2] cd 1e [2] da 15 [2] c1 5b [2] fc }

  condition:
    any of them
}