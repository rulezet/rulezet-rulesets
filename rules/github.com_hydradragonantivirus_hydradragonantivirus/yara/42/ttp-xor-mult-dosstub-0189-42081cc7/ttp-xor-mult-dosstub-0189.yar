rule TTP_XOR_MULT_DOSStub_0189 {
  strings:
    $key_0189 = { 55 e1 [2] 21 f9 [2] 66 fb [2] 21 ea [2] 6f e6 [2] 63 ec [2] 74 e7 [2] 6f a9 [2] 52 }

  condition:
    any of them
}