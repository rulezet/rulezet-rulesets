rule TTP_XOR_MULT_DOSStub_42d4 {
  strings:
    $key_42d4 = { 16 bc [2] 62 a4 [2] 25 a6 [2] 62 b7 [2] 2c bb [2] 20 b1 [2] 37 ba [2] 2c f4 [2] 11 }

  condition:
    any of them
}