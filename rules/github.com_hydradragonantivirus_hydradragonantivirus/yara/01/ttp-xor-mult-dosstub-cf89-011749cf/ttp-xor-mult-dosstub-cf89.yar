rule TTP_XOR_MULT_DOSStub_cf89 {
  strings:
    $key_cf89 = { 9b e1 [2] ef f9 [2] a8 fb [2] ef ea [2] a1 e6 [2] ad ec [2] ba e7 [2] a1 a9 [2] 9c }

  condition:
    any of them
}