rule TTP_XOR_MULT_DOSStub_57dc {
  strings:
    $key_57dc = { 03 b4 [2] 77 ac [2] 30 ae [2] 77 bf [2] 39 b3 [2] 35 b9 [2] 22 b2 [2] 39 fc [2] 04 }

  condition:
    any of them
}