rule TTP_XOR_MULT_DOSStub_318f {
  strings:
    $key_318f = { 65 e7 [2] 11 ff [2] 56 fd [2] 11 ec [2] 5f e0 [2] 53 ea [2] 44 e1 [2] 5f af [2] 62 }

  condition:
    any of them
}