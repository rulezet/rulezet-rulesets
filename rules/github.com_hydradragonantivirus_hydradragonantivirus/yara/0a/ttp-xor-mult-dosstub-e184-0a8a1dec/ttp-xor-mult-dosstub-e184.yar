rule TTP_XOR_MULT_DOSStub_e184 {
  strings:
    $key_e184 = { b5 ec [2] c1 f4 [2] 86 f6 [2] c1 e7 [2] 8f eb [2] 83 e1 [2] 94 ea [2] 8f a4 [2] b2 }

  condition:
    any of them
}