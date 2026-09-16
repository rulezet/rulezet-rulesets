rule TTP_XOR_MULT_DOSStub_b391 {
  strings:
    $key_b391 = { e7 f9 [2] 93 e1 [2] d4 e3 [2] 93 f2 [2] dd fe [2] d1 f4 [2] c6 ff [2] dd b1 [2] e0 }

  condition:
    any of them
}