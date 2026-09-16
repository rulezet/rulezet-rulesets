rule TTP_XOR_MULT_DOSStub_bc86 {
  strings:
    $key_bc86 = { e8 ee [2] 9c f6 [2] db f4 [2] 9c e5 [2] d2 e9 [2] de e3 [2] c9 e8 [2] d2 a6 [2] ef }

  condition:
    any of them
}