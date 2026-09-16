rule TTP_XOR_MULT_DOSStub_24dc {
  strings:
    $key_24dc = { 70 b4 [2] 04 ac [2] 43 ae [2] 04 bf [2] 4a b3 [2] 46 b9 [2] 51 b2 [2] 4a fc [2] 77 }

  condition:
    any of them
}