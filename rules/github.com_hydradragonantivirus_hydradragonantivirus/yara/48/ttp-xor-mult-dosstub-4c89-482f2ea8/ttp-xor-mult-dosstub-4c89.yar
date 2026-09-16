rule TTP_XOR_MULT_DOSStub_4c89 {
  strings:
    $key_4c89 = { 18 e1 [2] 6c f9 [2] 2b fb [2] 6c ea [2] 22 e6 [2] 2e ec [2] 39 e7 [2] 22 a9 [2] 1f }

  condition:
    any of them
}