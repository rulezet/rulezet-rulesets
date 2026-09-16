rule TTP_XOR_MULT_DOSStub_bc84 {
  strings:
    $key_bc84 = { e8 ec [2] 9c f4 [2] db f6 [2] 9c e7 [2] d2 eb [2] de e1 [2] c9 ea [2] d2 a4 [2] ef }

  condition:
    any of them
}