rule TTP_XOR_MULT_DOSStub_b498 {
  strings:
    $key_b498 = { e0 f0 [2] 94 e8 [2] d3 ea [2] 94 fb [2] da f7 [2] d6 fd [2] c1 f6 [2] da b8 [2] e7 }

  condition:
    any of them
}