rule TTP_XOR_MULT_DOSStub_11dc {
  strings:
    $key_11dc = { 45 b4 [2] 31 ac [2] 76 ae [2] 31 bf [2] 7f b3 [2] 73 b9 [2] 64 b2 [2] 7f fc [2] 42 }

  condition:
    any of them
}