rule TTP_XOR_MULT_DOSStub_60d1 {
  strings:
    $key_60d1 = { 34 b9 [2] 40 a1 [2] 07 a3 [2] 40 b2 [2] 0e be [2] 02 b4 [2] 15 bf [2] 0e f1 [2] 33 }

  condition:
    any of them
}