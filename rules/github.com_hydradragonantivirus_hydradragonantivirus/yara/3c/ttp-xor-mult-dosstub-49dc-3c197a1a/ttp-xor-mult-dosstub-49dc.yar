rule TTP_XOR_MULT_DOSStub_49dc {
  strings:
    $key_49dc = { 1d b4 [2] 69 ac [2] 2e ae [2] 69 bf [2] 27 b3 [2] 2b b9 [2] 3c b2 [2] 27 fc [2] 1a }

  condition:
    any of them
}