rule TTP_XOR_MULT_DOSStub_42da {
  strings:
    $key_42da = { 16 b2 [2] 62 aa [2] 25 a8 [2] 62 b9 [2] 2c b5 [2] 20 bf [2] 37 b4 [2] 2c fa [2] 11 }

  condition:
    any of them
}