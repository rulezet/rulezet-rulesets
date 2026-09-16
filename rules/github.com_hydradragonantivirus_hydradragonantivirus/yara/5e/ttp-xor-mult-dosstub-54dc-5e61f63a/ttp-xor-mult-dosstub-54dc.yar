rule TTP_XOR_MULT_DOSStub_54dc {
  strings:
    $key_54dc = { 00 b4 [2] 74 ac [2] 33 ae [2] 74 bf [2] 3a b3 [2] 36 b9 [2] 21 b2 [2] 3a fc [2] 07 }

  condition:
    any of them
}