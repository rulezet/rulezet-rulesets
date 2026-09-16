rule TTP_XOR_MULT_DOSStub_f4dc {
  strings:
    $key_f4dc = { a0 b4 [2] d4 ac [2] 93 ae [2] d4 bf [2] 9a b3 [2] 96 b9 [2] 81 b2 [2] 9a fc [2] a7 }

  condition:
    any of them
}