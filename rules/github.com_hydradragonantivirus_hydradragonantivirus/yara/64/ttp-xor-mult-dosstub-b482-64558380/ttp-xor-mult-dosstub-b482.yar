rule TTP_XOR_MULT_DOSStub_b482 {
  strings:
    $key_b482 = { e0 ea [2] 94 f2 [2] d3 f0 [2] 94 e1 [2] da ed [2] d6 e7 [2] c1 ec [2] da a2 [2] e7 }

  condition:
    any of them
}