rule TTP_XOR_MULT_DOSStub_b491 {
  strings:
    $key_b491 = { e0 f9 [2] 94 e1 [2] d3 e3 [2] 94 f2 [2] da fe [2] d6 f4 [2] c1 ff [2] da b1 [2] e7 }

  condition:
    any of them
}