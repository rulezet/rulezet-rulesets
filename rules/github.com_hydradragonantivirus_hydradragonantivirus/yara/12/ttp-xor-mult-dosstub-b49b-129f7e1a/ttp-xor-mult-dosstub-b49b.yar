rule TTP_XOR_MULT_DOSStub_b49b {
  strings:
    $key_b49b = { e0 f3 [2] 94 eb [2] d3 e9 [2] 94 f8 [2] da f4 [2] d6 fe [2] c1 f5 [2] da bb [2] e7 }

  condition:
    any of them
}