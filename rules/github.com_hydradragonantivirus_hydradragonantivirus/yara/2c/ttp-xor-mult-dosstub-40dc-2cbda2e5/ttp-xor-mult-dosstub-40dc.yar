rule TTP_XOR_MULT_DOSStub_40dc {
  strings:
    $key_40dc = { 14 b4 [2] 60 ac [2] 27 ae [2] 60 bf [2] 2e b3 [2] 22 b9 [2] 35 b2 [2] 2e fc [2] 13 }

  condition:
    any of them
}