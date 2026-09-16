rule TTP_XOR_MULT_DOSStub_7a8f {
  strings:
    $key_7a8f = { 2e e7 [2] 5a ff [2] 1d fd [2] 5a ec [2] 14 e0 [2] 18 ea [2] 0f e1 [2] 14 af [2] 29 }

  condition:
    any of them
}