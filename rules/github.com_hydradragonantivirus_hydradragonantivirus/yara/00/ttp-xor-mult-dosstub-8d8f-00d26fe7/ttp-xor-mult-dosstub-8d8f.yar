rule TTP_XOR_MULT_DOSStub_8d8f {
  strings:
    $key_8d8f = { d9 e7 [2] ad ff [2] ea fd [2] ad ec [2] e3 e0 [2] ef ea [2] f8 e1 [2] e3 af [2] de }

  condition:
    any of them
}