rule TTP_XOR_MULT_DOSStub_55d7 {
  strings:
    $key_55d7 = { 01 bf [2] 75 a7 [2] 32 a5 [2] 75 b4 [2] 3b b8 [2] 37 b2 [2] 20 b9 [2] 3b f7 [2] 06 }

  condition:
    any of them
}