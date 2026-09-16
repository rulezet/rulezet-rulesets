rule TTP_XOR_MULT_DOSStub_5c89 {
  strings:
    $key_5c89 = { 08 e1 [2] 7c f9 [2] 3b fb [2] 7c ea [2] 32 e6 [2] 3e ec [2] 29 e7 [2] 32 a9 [2] 0f }

  condition:
    any of them
}