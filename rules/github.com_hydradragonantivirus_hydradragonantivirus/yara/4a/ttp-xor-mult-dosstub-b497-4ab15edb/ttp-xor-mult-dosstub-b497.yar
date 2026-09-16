rule TTP_XOR_MULT_DOSStub_b497 {
  strings:
    $key_b497 = { e0 ff [2] 94 e7 [2] d3 e5 [2] 94 f4 [2] da f8 [2] d6 f2 [2] c1 f9 [2] da b7 [2] e7 }

  condition:
    any of them
}