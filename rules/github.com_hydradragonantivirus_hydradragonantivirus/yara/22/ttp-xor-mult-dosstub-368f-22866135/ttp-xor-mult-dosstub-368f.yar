rule TTP_XOR_MULT_DOSStub_368f {
  strings:
    $key_368f = { 62 e7 [2] 16 ff [2] 51 fd [2] 16 ec [2] 58 e0 [2] 54 ea [2] 43 e1 [2] 58 af [2] 65 }

  condition:
    any of them
}