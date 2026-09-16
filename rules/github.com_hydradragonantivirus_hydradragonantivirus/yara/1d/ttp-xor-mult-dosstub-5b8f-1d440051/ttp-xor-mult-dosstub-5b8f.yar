rule TTP_XOR_MULT_DOSStub_5b8f {
  strings:
    $key_5b8f = { 0f e7 [2] 7b ff [2] 3c fd [2] 7b ec [2] 35 e0 [2] 39 ea [2] 2e e1 [2] 35 af [2] 08 }

  condition:
    any of them
}