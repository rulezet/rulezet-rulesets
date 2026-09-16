rule TTP_XOR_MULT_DOSStub_468f {
  strings:
    $key_468f = { 12 e7 [2] 66 ff [2] 21 fd [2] 66 ec [2] 28 e0 [2] 24 ea [2] 33 e1 [2] 28 af [2] 15 }

  condition:
    any of them
}