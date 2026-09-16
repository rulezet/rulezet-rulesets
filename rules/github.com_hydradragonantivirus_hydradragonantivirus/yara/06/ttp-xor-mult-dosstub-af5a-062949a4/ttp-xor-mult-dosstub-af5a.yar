rule TTP_XOR_MULT_DOSStub_af5a {
  strings:
    $key_af5a = { fb 32 [2] 8f 2a [2] c8 28 [2] 8f 39 [2] c1 35 [2] cd 3f [2] da 34 [2] c1 7a [2] fc }

  condition:
    any of them
}