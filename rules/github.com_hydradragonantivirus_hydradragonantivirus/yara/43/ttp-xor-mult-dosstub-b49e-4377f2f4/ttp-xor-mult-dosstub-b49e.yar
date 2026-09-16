rule TTP_XOR_MULT_DOSStub_b49e {
  strings:
    $key_b49e = { e0 f6 [2] 94 ee [2] d3 ec [2] 94 fd [2] da f1 [2] d6 fb [2] c1 f0 [2] da be [2] e7 }

  condition:
    any of them
}