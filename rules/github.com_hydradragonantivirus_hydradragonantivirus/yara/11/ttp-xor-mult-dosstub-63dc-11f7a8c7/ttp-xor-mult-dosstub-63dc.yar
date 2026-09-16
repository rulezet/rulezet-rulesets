rule TTP_XOR_MULT_DOSStub_63dc {
  strings:
    $key_63dc = { 37 b4 [2] 43 ac [2] 04 ae [2] 43 bf [2] 0d b3 [2] 01 b9 [2] 16 b2 [2] 0d fc [2] 30 }

  condition:
    any of them
}