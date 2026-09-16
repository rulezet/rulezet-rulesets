rule TTP_XOR_MULT_DOSStub_e2dc {
  strings:
    $key_e2dc = { b6 b4 [2] c2 ac [2] 85 ae [2] c2 bf [2] 8c b3 [2] 80 b9 [2] 97 b2 [2] 8c fc [2] b1 }

  condition:
    any of them
}