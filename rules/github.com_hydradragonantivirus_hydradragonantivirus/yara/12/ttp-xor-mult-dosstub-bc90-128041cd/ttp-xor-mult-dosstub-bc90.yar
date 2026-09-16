rule TTP_XOR_MULT_DOSStub_bc90 {
  strings:
    $key_bc90 = { e8 f8 [2] 9c e0 [2] db e2 [2] 9c f3 [2] d2 ff [2] de f5 [2] c9 fe [2] d2 b0 [2] ef }

  condition:
    any of them
}