rule TTP_XOR_MULT_DOSStub_08dc {
  strings:
    $key_08dc = { 5c b4 [2] 28 ac [2] 6f ae [2] 28 bf [2] 66 b3 [2] 6a b9 [2] 7d b2 [2] 66 fc [2] 5b }

  condition:
    any of them
}