rule TTP_XOR_MULT_DOSStub_33db {
  strings:
    $key_33db = { 67 b3 [2] 13 ab [2] 54 a9 [2] 13 b8 [2] 5d b4 [2] 51 be [2] 46 b5 [2] 5d fb [2] 60 }

  condition:
    any of them
}