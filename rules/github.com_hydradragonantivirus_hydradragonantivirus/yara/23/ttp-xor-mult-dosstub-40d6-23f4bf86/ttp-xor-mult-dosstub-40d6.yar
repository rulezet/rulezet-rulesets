rule TTP_XOR_MULT_DOSStub_40d6 {
  strings:
    $key_40d6 = { 14 be [2] 60 a6 [2] 27 a4 [2] 60 b5 [2] 2e b9 [2] 22 b3 [2] 35 b8 [2] 2e f6 [2] 13 }

  condition:
    any of them
}