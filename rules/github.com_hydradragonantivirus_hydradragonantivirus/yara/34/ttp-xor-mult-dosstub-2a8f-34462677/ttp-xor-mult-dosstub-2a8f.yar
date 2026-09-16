rule TTP_XOR_MULT_DOSStub_2a8f {
  strings:
    $key_2a8f = { 7e e7 [2] 0a ff [2] 4d fd [2] 0a ec [2] 44 e0 [2] 48 ea [2] 5f e1 [2] 44 af [2] 79 }

  condition:
    any of them
}