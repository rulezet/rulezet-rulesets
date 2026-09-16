rule TTP_XOR_MULT_DOSStub_0c8f {
  strings:
    $key_0c8f = { 58 e7 [2] 2c ff [2] 6b fd [2] 2c ec [2] 62 e0 [2] 6e ea [2] 79 e1 [2] 62 af [2] 5f }

  condition:
    any of them
}