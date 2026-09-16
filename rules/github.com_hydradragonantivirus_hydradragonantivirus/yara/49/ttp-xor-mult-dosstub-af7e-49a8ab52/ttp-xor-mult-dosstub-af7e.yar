rule TTP_XOR_MULT_DOSStub_af7e {
  strings:
    $key_af7e = { fb 16 [2] 8f 0e [2] c8 0c [2] 8f 1d [2] c1 11 [2] cd 1b [2] da 10 [2] c1 5e [2] fc }

  condition:
    any of them
}