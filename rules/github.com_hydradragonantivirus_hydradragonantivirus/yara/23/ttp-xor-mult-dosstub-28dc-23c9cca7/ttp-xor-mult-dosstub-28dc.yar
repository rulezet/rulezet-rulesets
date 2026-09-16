rule TTP_XOR_MULT_DOSStub_28dc {
  strings:
    $key_28dc = { 7c b4 [2] 08 ac [2] 4f ae [2] 08 bf [2] 46 b3 [2] 4a b9 [2] 5d b2 [2] 46 fc [2] 7b }

  condition:
    any of them
}