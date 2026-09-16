rule TTP_XOR_MULT_DOSStub_2c89 {
  strings:
    $key_2c89 = { 78 e1 [2] 0c f9 [2] 4b fb [2] 0c ea [2] 42 e6 [2] 4e ec [2] 59 e7 [2] 42 a9 [2] 7f }

  condition:
    any of them
}