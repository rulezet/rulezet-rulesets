rule TTP_XOR_MULT_DOSStub_15dc {
  strings:
    $key_15dc = { 41 b4 [2] 35 ac [2] 72 ae [2] 35 bf [2] 7b b3 [2] 77 b9 [2] 60 b2 [2] 7b fc [2] 46 }

  condition:
    any of them
}