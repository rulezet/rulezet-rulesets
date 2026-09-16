rule TTP_XOR_MULT_DOSStub_0389 {
  strings:
    $key_0389 = { 57 e1 [2] 23 f9 [2] 64 fb [2] 23 ea [2] 6d e6 [2] 61 ec [2] 76 e7 [2] 6d a9 [2] 50 }

  condition:
    any of them
}