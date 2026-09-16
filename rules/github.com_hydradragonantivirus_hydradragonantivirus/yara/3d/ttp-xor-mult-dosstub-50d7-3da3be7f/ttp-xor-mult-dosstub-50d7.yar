rule TTP_XOR_MULT_DOSStub_50d7 {
  strings:
    $key_50d7 = { 04 bf [2] 70 a7 [2] 37 a5 [2] 70 b4 [2] 3e b8 [2] 32 b2 [2] 25 b9 [2] 3e f7 [2] 03 }

  condition:
    any of them
}