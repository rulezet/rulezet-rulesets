rule TTP_XOR_MULT_DOSStub_06dc {
  strings:
    $key_06dc = { 52 b4 [2] 26 ac [2] 61 ae [2] 26 bf [2] 68 b3 [2] 64 b9 [2] 73 b2 [2] 68 fc [2] 55 }

  condition:
    any of them
}