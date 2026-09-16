rule TTP_XOR_MULT_DOSStub_46dc {
  strings:
    $key_46dc = { 12 b4 [2] 66 ac [2] 21 ae [2] 66 bf [2] 28 b3 [2] 24 b9 [2] 33 b2 [2] 28 fc [2] 15 }

  condition:
    any of them
}