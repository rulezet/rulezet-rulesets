rule TTP_XOR_MULT_DOSStub_b496 {
  strings:
    $key_b496 = { e0 fe [2] 94 e6 [2] d3 e4 [2] 94 f5 [2] da f9 [2] d6 f3 [2] c1 f8 [2] da b6 [2] e7 }

  condition:
    any of them
}