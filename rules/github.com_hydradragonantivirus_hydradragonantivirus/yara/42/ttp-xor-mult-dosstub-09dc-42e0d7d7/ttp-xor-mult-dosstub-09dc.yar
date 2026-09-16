rule TTP_XOR_MULT_DOSStub_09dc {
  strings:
    $key_09dc = { 5d b4 [2] 29 ac [2] 6e ae [2] 29 bf [2] 67 b3 [2] 6b b9 [2] 7c b2 [2] 67 fc [2] 5a }

  condition:
    any of them
}