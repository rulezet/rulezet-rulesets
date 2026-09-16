rule TTP_XOR_MULT_DOSStub_1489 {
  strings:
    $key_1489 = { 40 e1 [2] 34 f9 [2] 73 fb [2] 34 ea [2] 7a e6 [2] 76 ec [2] 61 e7 [2] 7a a9 [2] 47 }

  condition:
    any of them
}