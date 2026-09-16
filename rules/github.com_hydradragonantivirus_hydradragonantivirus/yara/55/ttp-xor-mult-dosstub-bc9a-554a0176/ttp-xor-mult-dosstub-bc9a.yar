rule TTP_XOR_MULT_DOSStub_bc9a {
  strings:
    $key_bc9a = { e8 f2 [2] 9c ea [2] db e8 [2] 9c f9 [2] d2 f5 [2] de ff [2] c9 f4 [2] d2 ba [2] ef }

  condition:
    any of them
}