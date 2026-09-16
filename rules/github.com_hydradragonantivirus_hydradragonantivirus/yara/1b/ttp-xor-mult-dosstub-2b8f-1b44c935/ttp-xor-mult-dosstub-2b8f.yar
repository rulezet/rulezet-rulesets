rule TTP_XOR_MULT_DOSStub_2b8f {
  strings:
    $key_2b8f = { 7f e7 [2] 0b ff [2] 4c fd [2] 0b ec [2] 45 e0 [2] 49 ea [2] 5e e1 [2] 45 af [2] 78 }

  condition:
    any of them
}