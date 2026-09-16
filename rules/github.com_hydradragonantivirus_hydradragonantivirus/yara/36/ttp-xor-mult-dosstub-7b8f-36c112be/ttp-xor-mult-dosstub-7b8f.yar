rule TTP_XOR_MULT_DOSStub_7b8f {
  strings:
    $key_7b8f = { 2f e7 [2] 5b ff [2] 1c fd [2] 5b ec [2] 15 e0 [2] 19 ea [2] 0e e1 [2] 15 af [2] 28 }

  condition:
    any of them
}