rule TTP_XOR_MULT_DOSStub_b0d7 {
  strings:
    $key_b0d7 = { e4 bf [2] 90 a7 [2] d7 a5 [2] 90 b4 [2] de b8 [2] d2 b2 [2] c5 b9 [2] de f7 [2] e3 }

  condition:
    any of them
}