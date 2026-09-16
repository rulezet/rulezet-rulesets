rule TTP_XOR_MULT_DOSStub_4189 {
  strings:
    $key_4189 = { 15 e1 [2] 61 f9 [2] 26 fb [2] 61 ea [2] 2f e6 [2] 23 ec [2] 34 e7 [2] 2f a9 [2] 12 }

  condition:
    any of them
}