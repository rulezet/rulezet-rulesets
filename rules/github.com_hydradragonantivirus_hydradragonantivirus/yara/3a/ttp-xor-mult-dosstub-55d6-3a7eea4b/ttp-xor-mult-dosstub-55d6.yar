rule TTP_XOR_MULT_DOSStub_55d6 {
  strings:
    $key_55d6 = { 01 be [2] 75 a6 [2] 32 a4 [2] 75 b5 [2] 3b b9 [2] 37 b3 [2] 20 b8 [2] 3b f6 [2] 06 }

  condition:
    any of them
}