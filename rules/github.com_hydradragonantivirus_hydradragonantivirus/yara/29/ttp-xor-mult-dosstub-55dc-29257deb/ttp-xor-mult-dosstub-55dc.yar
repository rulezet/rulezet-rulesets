rule TTP_XOR_MULT_DOSStub_55dc {
  strings:
    $key_55dc = { 01 b4 [2] 75 ac [2] 32 ae [2] 75 bf [2] 3b b3 [2] 37 b9 [2] 20 b2 [2] 3b fc [2] 06 }

  condition:
    any of them
}