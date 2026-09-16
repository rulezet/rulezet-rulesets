rule TTP_XOR_MULT_DOSStub_bc89 {
  strings:
    $key_bc89 = { e8 e1 [2] 9c f9 [2] db fb [2] 9c ea [2] d2 e6 [2] de ec [2] c9 e7 [2] d2 a9 [2] ef }

  condition:
    any of them
}