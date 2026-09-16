rule TTP_XOR_MULT_DOSStub_b691 {
  strings:
    $key_b691 = { e2 f9 [2] 96 e1 [2] d1 e3 [2] 96 f2 [2] d8 fe [2] d4 f4 [2] c3 ff [2] d8 b1 [2] e5 }

  condition:
    any of them
}