rule TTP_XOR_MULT_DOSStub_7d8f {
  strings:
    $key_7d8f = { 29 e7 [2] 5d ff [2] 1a fd [2] 5d ec [2] 13 e0 [2] 1f ea [2] 08 e1 [2] 13 af [2] 2e }

  condition:
    any of them
}