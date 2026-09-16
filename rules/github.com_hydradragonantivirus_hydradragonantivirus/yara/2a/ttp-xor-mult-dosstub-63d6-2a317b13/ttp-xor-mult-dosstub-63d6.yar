rule TTP_XOR_MULT_DOSStub_63d6 {
  strings:
    $key_63d6 = { 37 be [2] 43 a6 [2] 04 a4 [2] 43 b5 [2] 0d b9 [2] 01 b3 [2] 16 b8 [2] 0d f6 [2] 30 }

  condition:
    any of them
}