rule TTP_XOR_MULT_DOSStub_78dc {
  strings:
    $key_78dc = { 2c b4 [2] 58 ac [2] 1f ae [2] 58 bf [2] 16 b3 [2] 1a b9 [2] 0d b2 [2] 16 fc [2] 2b }

  condition:
    any of them
}