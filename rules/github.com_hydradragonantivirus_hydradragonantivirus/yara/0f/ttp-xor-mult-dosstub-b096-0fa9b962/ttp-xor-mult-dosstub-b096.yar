rule TTP_XOR_MULT_DOSStub_b096 {
  strings:
    $key_b096 = { e4 fe [2] 90 e6 [2] d7 e4 [2] 90 f5 [2] de f9 [2] d2 f3 [2] c5 f8 [2] de b6 [2] e3 }

  condition:
    any of them
}