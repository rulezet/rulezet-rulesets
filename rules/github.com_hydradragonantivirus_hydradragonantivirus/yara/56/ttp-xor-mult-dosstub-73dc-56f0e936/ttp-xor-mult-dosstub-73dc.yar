rule TTP_XOR_MULT_DOSStub_73dc {
  strings:
    $key_73dc = { 27 b4 [2] 53 ac [2] 14 ae [2] 53 bf [2] 1d b3 [2] 11 b9 [2] 06 b2 [2] 1d fc [2] 20 }

  condition:
    any of them
}