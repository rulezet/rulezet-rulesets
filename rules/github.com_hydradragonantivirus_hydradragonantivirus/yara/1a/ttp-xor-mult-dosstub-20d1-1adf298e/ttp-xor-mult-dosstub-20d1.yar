rule TTP_XOR_MULT_DOSStub_20d1 {
  strings:
    $key_20d1 = { 74 b9 [2] 00 a1 [2] 47 a3 [2] 00 b2 [2] 4e be [2] 42 b4 [2] 55 bf [2] 4e f1 [2] 73 }

  condition:
    any of them
}