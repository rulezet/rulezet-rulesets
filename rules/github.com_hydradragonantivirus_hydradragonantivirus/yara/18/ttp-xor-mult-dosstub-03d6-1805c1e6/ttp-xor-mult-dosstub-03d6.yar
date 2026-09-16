rule TTP_XOR_MULT_DOSStub_03d6 {
  strings:
    $key_03d6 = { 57 be [2] 23 a6 [2] 64 a4 [2] 23 b5 [2] 6d b9 [2] 61 b3 [2] 76 b8 [2] 6d f6 [2] 50 }

  condition:
    any of them
}