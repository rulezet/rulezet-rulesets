rule TTP_XOR_MULT_DOSStub_f5dc {
  strings:
    $key_f5dc = { a1 b4 [2] d5 ac [2] 92 ae [2] d5 bf [2] 9b b3 [2] 97 b9 [2] 80 b2 [2] 9b fc [2] a6 }

  condition:
    any of them
}