rule TTP_XOR_MULT_DOSStub_d8dc {
  strings:
    $key_d8dc = { 8c b4 [2] f8 ac [2] bf ae [2] f8 bf [2] b6 b3 [2] ba b9 [2] ad b2 [2] b6 fc [2] 8b }

  condition:
    any of them
}