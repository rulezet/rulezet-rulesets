rule TTP_XOR_MULT_DOSStub_ac89 {
  strings:
    $key_ac89 = { f8 e1 [2] 8c f9 [2] cb fb [2] 8c ea [2] c2 e6 [2] ce ec [2] d9 e7 [2] c2 a9 [2] ff }

  condition:
    any of them
}