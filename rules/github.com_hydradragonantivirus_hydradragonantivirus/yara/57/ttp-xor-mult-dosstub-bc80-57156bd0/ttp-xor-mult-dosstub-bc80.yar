rule TTP_XOR_MULT_DOSStub_bc80 {
  strings:
    $key_bc80 = { e8 e8 [2] 9c f0 [2] db f2 [2] 9c e3 [2] d2 ef [2] de e5 [2] c9 ee [2] d2 a0 [2] ef }

  condition:
    any of them
}