rule TTP_XOR_MULT_DOSStub_bc96 {
  strings:
    $key_bc96 = { e8 fe [2] 9c e6 [2] db e4 [2] 9c f5 [2] d2 f9 [2] de f3 [2] c9 f8 [2] d2 b6 [2] ef }

  condition:
    any of them
}