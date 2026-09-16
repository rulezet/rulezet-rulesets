rule TTP_XOR_MULT_DOSStub_b18f {
  strings:
    $key_b18f = { e5 e7 [2] 91 ff [2] d6 fd [2] 91 ec [2] df e0 [2] d3 ea [2] c4 e1 [2] df af [2] e2 }

  condition:
    any of them
}