rule TTP_XOR_MULT_DOSStub_0d8f {
  strings:
    $key_0d8f = { 59 e7 [2] 2d ff [2] 6a fd [2] 2d ec [2] 63 e0 [2] 6f ea [2] 78 e1 [2] 63 af [2] 5e }

  condition:
    any of them
}