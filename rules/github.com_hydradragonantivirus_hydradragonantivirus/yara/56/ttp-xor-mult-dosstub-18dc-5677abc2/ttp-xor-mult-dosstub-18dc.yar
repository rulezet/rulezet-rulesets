rule TTP_XOR_MULT_DOSStub_18dc {
  strings:
    $key_18dc = { 4c b4 [2] 38 ac [2] 7f ae [2] 38 bf [2] 76 b3 [2] 7a b9 [2] 6d b2 [2] 76 fc [2] 4b }

  condition:
    any of them
}