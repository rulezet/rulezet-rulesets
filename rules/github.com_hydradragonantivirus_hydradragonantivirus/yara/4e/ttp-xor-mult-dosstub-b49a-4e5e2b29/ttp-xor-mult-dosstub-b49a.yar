rule TTP_XOR_MULT_DOSStub_b49a {
  strings:
    $key_b49a = { e0 f2 [2] 94 ea [2] d3 e8 [2] 94 f9 [2] da f5 [2] d6 ff [2] c1 f4 [2] da ba [2] e7 }

  condition:
    any of them
}