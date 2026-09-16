rule TTP_XOR_MULT_DOSStub_6d8f {
  strings:
    $key_6d8f = { 39 e7 [2] 4d ff [2] 0a fd [2] 4d ec [2] 03 e0 [2] 0f ea [2] 18 e1 [2] 03 af [2] 3e }

  condition:
    any of them
}