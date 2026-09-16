rule TTP_XOR_MULT_DOSStub_42d7 {
  strings:
    $key_42d7 = { 16 bf [2] 62 a7 [2] 25 a5 [2] 62 b4 [2] 2c b8 [2] 20 b2 [2] 37 b9 [2] 2c f7 [2] 11 }

  condition:
    any of them
}