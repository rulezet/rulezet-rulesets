rule TTP_XOR_MULT_DOSStub_50d1 {
  strings:
    $key_50d1 = { 04 b9 [2] 70 a1 [2] 37 a3 [2] 70 b2 [2] 3e be [2] 32 b4 [2] 25 bf [2] 3e f1 [2] 03 }

  condition:
    any of them
}