rule TTP_XOR_MULT_DOSStub_af5c {
  strings:
    $key_af5c = { fb 34 [2] 8f 2c [2] c8 2e [2] 8f 3f [2] c1 33 [2] cd 39 [2] da 32 [2] c1 7c [2] fc }

  condition:
    any of them
}