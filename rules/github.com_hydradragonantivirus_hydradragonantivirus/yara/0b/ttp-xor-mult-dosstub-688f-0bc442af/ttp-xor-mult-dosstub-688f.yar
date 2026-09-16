rule TTP_XOR_MULT_DOSStub_688f {
  strings:
    $key_688f = { 3c e7 [2] 48 ff [2] 0f fd [2] 48 ec [2] 06 e0 [2] 0a ea [2] 1d e1 [2] 06 af [2] 3b }

  condition:
    any of them
}