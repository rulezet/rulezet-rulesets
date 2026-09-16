rule TTP_XOR_MULT_DOSStub_70d6 {
  strings:
    $key_70d6 = { 24 be [2] 50 a6 [2] 17 a4 [2] 50 b5 [2] 1e b9 [2] 12 b3 [2] 05 b8 [2] 1e f6 [2] 23 }

  condition:
    any of them
}