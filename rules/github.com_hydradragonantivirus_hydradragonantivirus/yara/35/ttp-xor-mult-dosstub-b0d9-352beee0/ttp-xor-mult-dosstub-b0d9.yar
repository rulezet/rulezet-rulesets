rule TTP_XOR_MULT_DOSStub_b0d9 {
  strings:
    $key_b0d9 = { e4 b1 [2] 90 a9 [2] d7 ab [2] 90 ba [2] de b6 [2] d2 bc [2] c5 b7 [2] de f9 [2] e3 }

  condition:
    any of them
}