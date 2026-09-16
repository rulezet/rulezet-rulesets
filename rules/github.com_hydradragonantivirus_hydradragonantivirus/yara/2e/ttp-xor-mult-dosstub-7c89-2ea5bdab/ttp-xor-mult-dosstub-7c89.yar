rule TTP_XOR_MULT_DOSStub_7c89 {
  strings:
    $key_7c89 = { 28 e1 [2] 5c f9 [2] 1b fb [2] 5c ea [2] 12 e6 [2] 1e ec [2] 09 e7 [2] 12 a9 [2] 2f }

  condition:
    any of them
}