rule TTP_XOR_MULT_DOSStub_b5ca {
  strings:
    $key_b5ca = { e1 a2 [2] 95 ba [2] d2 b8 [2] 95 a9 [2] db a5 [2] d7 af [2] c0 a4 [2] db ea [2] e6 }

  condition:
    any of them
}