rule TTP_XOR_MULT_DOSStub_71dc {
  strings:
    $key_71dc = { 25 b4 [2] 51 ac [2] 16 ae [2] 51 bf [2] 1f b3 [2] 13 b9 [2] 04 b2 [2] 1f fc [2] 22 }

  condition:
    any of them
}