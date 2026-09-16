rule TTP_XOR_MULT_DOSStub_65dc {
  strings:
    $key_65dc = { 31 b4 [2] 45 ac [2] 02 ae [2] 45 bf [2] 0b b3 [2] 07 b9 [2] 10 b2 [2] 0b fc [2] 36 }

  condition:
    any of them
}