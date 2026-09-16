rule TTP_XOR_MULT_DOSStub_3089 {
  strings:
    $key_3089 = { 64 e1 [2] 10 f9 [2] 57 fb [2] 10 ea [2] 5e e6 [2] 52 ec [2] 45 e7 [2] 5e a9 [2] 63 }

  condition:
    any of them
}