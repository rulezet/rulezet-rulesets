rule TTP_XOR_MULT_DOSStub_bc95 {
  strings:
    $key_bc95 = { e8 fd [2] 9c e5 [2] db e7 [2] 9c f6 [2] d2 fa [2] de f0 [2] c9 fb [2] d2 b5 [2] ef }

  condition:
    any of them
}