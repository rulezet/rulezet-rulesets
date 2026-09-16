rule TTP_XOR_MULT_DOSStub_21dc {
  strings:
    $key_21dc = { 75 b4 [2] 01 ac [2] 46 ae [2] 01 bf [2] 4f b3 [2] 43 b9 [2] 54 b2 [2] 4f fc [2] 72 }

  condition:
    any of them
}