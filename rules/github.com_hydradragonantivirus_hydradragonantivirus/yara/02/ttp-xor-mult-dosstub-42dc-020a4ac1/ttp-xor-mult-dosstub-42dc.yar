rule TTP_XOR_MULT_DOSStub_42dc {
  strings:
    $key_42dc = { 16 b4 [2] 62 ac [2] 25 ae [2] 62 bf [2] 2c b3 [2] 20 b9 [2] 37 b2 [2] 2c fc [2] 11 }

  condition:
    any of them
}