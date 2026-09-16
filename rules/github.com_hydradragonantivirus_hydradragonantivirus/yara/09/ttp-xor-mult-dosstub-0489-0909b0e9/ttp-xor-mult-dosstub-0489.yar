rule TTP_XOR_MULT_DOSStub_0489 {
  strings:
    $key_0489 = { 50 e1 [2] 24 f9 [2] 63 fb [2] 24 ea [2] 6a e6 [2] 66 ec [2] 71 e7 [2] 6a a9 [2] 57 }

  condition:
    any of them
}