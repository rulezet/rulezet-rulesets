rule TTP_XOR_MULT_DOSStub_778f {
  strings:
    $key_778f = { 23 e7 [2] 57 ff [2] 10 fd [2] 57 ec [2] 19 e0 [2] 15 ea [2] 02 e1 [2] 19 af [2] 24 }

  condition:
    any of them
}