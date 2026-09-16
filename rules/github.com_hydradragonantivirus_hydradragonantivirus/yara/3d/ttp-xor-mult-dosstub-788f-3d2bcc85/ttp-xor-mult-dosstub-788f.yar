rule TTP_XOR_MULT_DOSStub_788f {
  strings:
    $key_788f = { 2c e7 [2] 58 ff [2] 1f fd [2] 58 ec [2] 16 e0 [2] 1a ea [2] 0d e1 [2] 16 af [2] 2b }

  condition:
    any of them
}