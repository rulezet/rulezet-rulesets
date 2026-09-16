rule TTP_XOR_MULT_DOSStub_0484 {
  strings:
    $key_0484 = { 50 ec [2] 24 f4 [2] 63 f6 [2] 24 e7 [2] 6a eb [2] 66 e1 [2] 71 ea [2] 6a a4 [2] 57 }

  condition:
    any of them
}