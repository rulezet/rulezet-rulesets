rule TTP_XOR_MULT_DOSStub_b4d7 {
  strings:
    $key_b4d7 = { e0 bf [2] 94 a7 [2] d3 a5 [2] 94 b4 [2] da b8 [2] d6 b2 [2] c1 b9 [2] da f7 [2] e7 }

  condition:
    any of them
}