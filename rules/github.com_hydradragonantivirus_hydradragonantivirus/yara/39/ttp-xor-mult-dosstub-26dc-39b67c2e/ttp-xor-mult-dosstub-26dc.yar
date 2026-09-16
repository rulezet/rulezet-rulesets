rule TTP_XOR_MULT_DOSStub_26dc {
  strings:
    $key_26dc = { 72 b4 [2] 06 ac [2] 41 ae [2] 06 bf [2] 48 b3 [2] 44 b9 [2] 53 b2 [2] 48 fc [2] 75 }

  condition:
    any of them
}