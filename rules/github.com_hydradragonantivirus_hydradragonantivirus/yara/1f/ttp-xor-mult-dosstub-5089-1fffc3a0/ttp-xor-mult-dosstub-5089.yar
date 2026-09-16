rule TTP_XOR_MULT_DOSStub_5089 {
  strings:
    $key_5089 = { 04 e1 [2] 70 f9 [2] 37 fb [2] 70 ea [2] 3e e6 [2] 32 ec [2] 25 e7 [2] 3e a9 [2] 03 }

  condition:
    any of them
}