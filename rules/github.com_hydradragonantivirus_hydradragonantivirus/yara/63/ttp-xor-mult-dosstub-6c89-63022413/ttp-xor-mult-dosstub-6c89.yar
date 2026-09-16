rule TTP_XOR_MULT_DOSStub_6c89 {
  strings:
    $key_6c89 = { 38 e1 [2] 4c f9 [2] 0b fb [2] 4c ea [2] 02 e6 [2] 0e ec [2] 19 e7 [2] 02 a9 [2] 3f }

  condition:
    any of them
}