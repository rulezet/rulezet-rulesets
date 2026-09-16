rule TTP_XOR_MULT_DOSStub_6a8f {
  strings:
    $key_6a8f = { 3e e7 [2] 4a ff [2] 0d fd [2] 4a ec [2] 04 e0 [2] 08 ea [2] 1f e1 [2] 04 af [2] 39 }

  condition:
    any of them
}