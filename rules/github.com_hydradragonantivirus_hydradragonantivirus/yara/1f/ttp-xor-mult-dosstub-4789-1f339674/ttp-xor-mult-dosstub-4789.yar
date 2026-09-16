rule TTP_XOR_MULT_DOSStub_4789 {
  strings:
    $key_4789 = { 13 e1 [2] 67 f9 [2] 20 fb [2] 67 ea [2] 29 e6 [2] 25 ec [2] 32 e7 [2] 29 a9 [2] 14 }

  condition:
    any of them
}