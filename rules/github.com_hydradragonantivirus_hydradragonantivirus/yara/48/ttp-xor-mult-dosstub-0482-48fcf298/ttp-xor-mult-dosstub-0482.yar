rule TTP_XOR_MULT_DOSStub_0482 {
  strings:
    $key_0482 = { 50 ea [2] 24 f2 [2] 63 f0 [2] 24 e1 [2] 6a ed [2] 66 e7 [2] 71 ec [2] 6a a2 [2] 57 }

  condition:
    any of them
}