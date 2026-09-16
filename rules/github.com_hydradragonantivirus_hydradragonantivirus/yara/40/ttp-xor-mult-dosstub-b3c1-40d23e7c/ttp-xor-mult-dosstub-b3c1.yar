rule TTP_XOR_MULT_DOSStub_b3c1 {
  strings:
    $key_b3c1 = { e7 a9 [2] 93 b1 [2] d4 b3 [2] 93 a2 [2] dd ae [2] d1 a4 [2] c6 af [2] dd e1 [2] e0 }

  condition:
    any of them
}