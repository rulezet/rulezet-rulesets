rule TTP_XOR_MULT_DOSStub_af83 {
  strings:
    $key_af83 = { fb eb [2] 8f f3 [2] c8 f1 [2] 8f e0 [2] c1 ec [2] cd e6 [2] da ed [2] c1 a3 [2] fc }

  condition:
    any of them
}