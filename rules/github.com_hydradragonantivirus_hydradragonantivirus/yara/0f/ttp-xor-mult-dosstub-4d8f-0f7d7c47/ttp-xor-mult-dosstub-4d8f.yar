rule TTP_XOR_MULT_DOSStub_4d8f {
  strings:
    $key_4d8f = { 19 e7 [2] 6d ff [2] 2a fd [2] 6d ec [2] 23 e0 [2] 2f ea [2] 38 e1 [2] 23 af [2] 1e }

  condition:
    any of them
}