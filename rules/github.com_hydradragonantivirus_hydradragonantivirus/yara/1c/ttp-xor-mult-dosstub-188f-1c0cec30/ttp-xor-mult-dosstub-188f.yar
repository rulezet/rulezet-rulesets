rule TTP_XOR_MULT_DOSStub_188f {
  strings:
    $key_188f = { 4c e7 [2] 38 ff [2] 7f fd [2] 38 ec [2] 76 e0 [2] 7a ea [2] 6d e1 [2] 76 af [2] 4b }

  condition:
    any of them
}