rule TTP_XOR_MULT_DOSStub_4a8f {
  strings:
    $key_4a8f = { 1e e7 [2] 6a ff [2] 2d fd [2] 6a ec [2] 24 e0 [2] 28 ea [2] 3f e1 [2] 24 af [2] 19 }

  condition:
    any of them
}