rule TTP_XOR_MULT_DOSStub_50dc {
  strings:
    $key_50dc = { 04 b4 [2] 70 ac [2] 37 ae [2] 70 bf [2] 3e b3 [2] 32 b9 [2] 25 b2 [2] 3e fc [2] 03 }

  condition:
    any of them
}