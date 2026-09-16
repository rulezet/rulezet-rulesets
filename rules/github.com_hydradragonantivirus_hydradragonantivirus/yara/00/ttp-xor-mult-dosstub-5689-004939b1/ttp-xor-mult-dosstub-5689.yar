rule TTP_XOR_MULT_DOSStub_5689 {
  strings:
    $key_5689 = { 02 e1 [2] 76 f9 [2] 31 fb [2] 76 ea [2] 38 e6 [2] 34 ec [2] 23 e7 [2] 38 a9 [2] 05 }

  condition:
    any of them
}