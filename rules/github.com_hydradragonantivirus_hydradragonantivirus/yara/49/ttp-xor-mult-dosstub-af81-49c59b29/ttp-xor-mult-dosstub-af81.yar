rule TTP_XOR_MULT_DOSStub_af81 {
  strings:
    $key_af81 = { fb e9 [2] 8f f1 [2] c8 f3 [2] 8f e2 [2] c1 ee [2] cd e4 [2] da ef [2] c1 a1 [2] fc }

  condition:
    any of them
}