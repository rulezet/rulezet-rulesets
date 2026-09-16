rule TTP_XOR_MULT_DOSStub_14dc {
  strings:
    $key_14dc = { 40 b4 [2] 34 ac [2] 73 ae [2] 34 bf [2] 7a b3 [2] 76 b9 [2] 61 b2 [2] 7a fc [2] 47 }

  condition:
    any of them
}