rule TTP_XOR_MULT_DOSStub_50d6 {
  strings:
    $key_50d6 = { 04 be [2] 70 a6 [2] 37 a4 [2] 70 b5 [2] 3e b9 [2] 32 b3 [2] 25 b8 [2] 3e f6 [2] 03 }

  condition:
    any of them
}