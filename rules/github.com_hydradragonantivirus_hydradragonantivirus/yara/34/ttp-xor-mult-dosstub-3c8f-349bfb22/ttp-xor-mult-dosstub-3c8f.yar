rule TTP_XOR_MULT_DOSStub_3c8f {
  strings:
    $key_3c8f = { 68 e7 [2] 1c ff [2] 5b fd [2] 1c ec [2] 52 e0 [2] 5e ea [2] 49 e1 [2] 52 af [2] 6f }

  condition:
    any of them
}