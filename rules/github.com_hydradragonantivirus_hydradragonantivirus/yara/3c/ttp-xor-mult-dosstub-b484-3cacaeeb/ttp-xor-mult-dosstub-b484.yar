rule TTP_XOR_MULT_DOSStub_b484 {
  strings:
    $key_b484 = { e0 ec [2] 94 f4 [2] d3 f6 [2] 94 e7 [2] da eb [2] d6 e1 [2] c1 ea [2] da a4 [2] e7 }

  condition:
    any of them
}