rule TTP_XOR_MULT_DOSStub_02dc {
  strings:
    $key_02dc = { 56 b4 [2] 22 ac [2] 65 ae [2] 22 bf [2] 6c b3 [2] 60 b9 [2] 77 b2 [2] 6c fc [2] 51 }

  condition:
    any of them
}