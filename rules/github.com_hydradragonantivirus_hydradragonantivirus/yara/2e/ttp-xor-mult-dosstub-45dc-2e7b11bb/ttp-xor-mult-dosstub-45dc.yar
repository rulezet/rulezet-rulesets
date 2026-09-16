rule TTP_XOR_MULT_DOSStub_45dc {
  strings:
    $key_45dc = { 11 b4 [2] 65 ac [2] 22 ae [2] 65 bf [2] 2b b3 [2] 27 b9 [2] 30 b2 [2] 2b fc [2] 16 }

  condition:
    any of them
}