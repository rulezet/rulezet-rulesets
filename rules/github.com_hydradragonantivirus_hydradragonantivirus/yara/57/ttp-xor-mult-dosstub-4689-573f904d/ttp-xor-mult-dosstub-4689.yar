rule TTP_XOR_MULT_DOSStub_4689 {
  strings:
    $key_4689 = { 12 e1 [2] 66 f9 [2] 21 fb [2] 66 ea [2] 28 e6 [2] 24 ec [2] 33 e7 [2] 28 a9 [2] 15 }

  condition:
    any of them
}