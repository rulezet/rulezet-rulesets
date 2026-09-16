rule TTP_XOR_MULT_DOSStub_b58f {
  strings:
    $key_b58f = { e1 e7 [2] 95 ff [2] d2 fd [2] 95 ec [2] db e0 [2] d7 ea [2] c0 e1 [2] db af [2] e6 }

  condition:
    any of them
}