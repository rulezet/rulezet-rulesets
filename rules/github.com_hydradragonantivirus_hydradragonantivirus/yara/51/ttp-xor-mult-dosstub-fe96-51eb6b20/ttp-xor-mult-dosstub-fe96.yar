rule TTP_XOR_MULT_DOSStub_fe96 {
  strings:
    $key_fe96 = { aa fe [2] de e6 [2] 99 e4 [2] de f5 [2] 90 f9 [2] 9c f3 [2] 8b f8 [2] 90 b6 [2] ad }

  condition:
    any of them
}