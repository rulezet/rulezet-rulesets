rule TTP_XOR_MULT_DOSStub_b08f {
  strings:
    $key_b08f = { e4 e7 [2] 90 ff [2] d7 fd [2] 90 ec [2] de e0 [2] d2 ea [2] c5 e1 [2] de af [2] e3 }

  condition:
    any of them
}