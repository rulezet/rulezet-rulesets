rule TTP_XOR_MULT_DOSStub_af8a {
  strings:
    $key_af8a = { fb e2 [2] 8f fa [2] c8 f8 [2] 8f e9 [2] c1 e5 [2] cd ef [2] da e4 [2] c1 aa [2] fc }

  condition:
    any of them
}