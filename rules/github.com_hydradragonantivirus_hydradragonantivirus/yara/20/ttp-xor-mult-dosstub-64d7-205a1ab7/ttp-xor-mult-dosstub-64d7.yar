rule TTP_XOR_MULT_DOSStub_64d7 {
  strings:
    $key_64d7 = { 30 bf [2] 44 a7 [2] 03 a5 [2] 44 b4 [2] 0a b8 [2] 06 b2 [2] 11 b9 [2] 0a f7 [2] 37 }

  condition:
    any of them
}