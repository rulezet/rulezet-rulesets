rule TTP_XOR_MULT_DOSStub_b0d4 {
  strings:
    $key_b0d4 = { e4 bc [2] 90 a4 [2] d7 a6 [2] 90 b7 [2] de bb [2] d2 b1 [2] c5 ba [2] de f4 [2] e3 }

  condition:
    any of them
}