rule TTP_XOR_MULT_DOSStub_31dc {
  strings:
    $key_31dc = { 65 b4 [2] 11 ac [2] 56 ae [2] 11 bf [2] 5f b3 [2] 53 b9 [2] 44 b2 [2] 5f fc [2] 62 }

  condition:
    any of them
}