rule TTP_XOR_MULT_DOSStub_40d1 {
  strings:
    $key_40d1 = { 14 b9 [2] 60 a1 [2] 27 a3 [2] 60 b2 [2] 2e be [2] 22 b4 [2] 35 bf [2] 2e f1 [2] 13 }

  condition:
    any of them
}