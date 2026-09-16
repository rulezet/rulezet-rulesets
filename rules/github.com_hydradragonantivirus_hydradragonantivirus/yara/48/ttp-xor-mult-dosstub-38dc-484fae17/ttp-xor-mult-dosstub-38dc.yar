rule TTP_XOR_MULT_DOSStub_38dc {
  strings:
    $key_38dc = { 6c b4 [2] 18 ac [2] 5f ae [2] 18 bf [2] 56 b3 [2] 5a b9 [2] 4d b2 [2] 56 fc [2] 6b }

  condition:
    any of them
}