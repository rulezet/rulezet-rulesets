rule TTP_XOR_MULT_DOSStub_29dc {
  strings:
    $key_29dc = { 7d b4 [2] 09 ac [2] 4e ae [2] 09 bf [2] 47 b3 [2] 4b b9 [2] 5c b2 [2] 47 fc [2] 7a }

  condition:
    any of them
}