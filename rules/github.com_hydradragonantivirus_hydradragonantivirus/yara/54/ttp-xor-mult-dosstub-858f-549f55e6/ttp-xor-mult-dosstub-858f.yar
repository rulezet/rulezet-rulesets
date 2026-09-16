rule TTP_XOR_MULT_DOSStub_858f {
  strings:
    $key_858f = { d1 e7 [2] a5 ff [2] e2 fd [2] a5 ec [2] eb e0 [2] e7 ea [2] f0 e1 [2] eb af [2] d6 }

  condition:
    any of them
}