rule TTP_XOR_MULT_DOSStub_1a8f {
  strings:
    $key_1a8f = { 4e e7 [2] 3a ff [2] 7d fd [2] 3a ec [2] 74 e0 [2] 78 ea [2] 6f e1 [2] 74 af [2] 49 }

  condition:
    any of them
}