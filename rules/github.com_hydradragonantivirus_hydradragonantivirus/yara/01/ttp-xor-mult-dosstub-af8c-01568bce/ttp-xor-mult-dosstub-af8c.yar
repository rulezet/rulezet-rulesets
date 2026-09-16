rule TTP_XOR_MULT_DOSStub_af8c {
  strings:
    $key_af8c = { fb e4 [2] 8f fc [2] c8 fe [2] 8f ef [2] c1 e3 [2] cd e9 [2] da e2 [2] c1 ac [2] fc }

  condition:
    any of them
}