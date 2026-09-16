rule TTP_XOR_MULT_DOSStub_bc8f {
  strings:
    $key_bc8f = { e8 e7 [2] 9c ff [2] db fd [2] 9c ec [2] d2 e0 [2] de ea [2] c9 e1 [2] d2 af [2] ef }

  condition:
    any of them
}