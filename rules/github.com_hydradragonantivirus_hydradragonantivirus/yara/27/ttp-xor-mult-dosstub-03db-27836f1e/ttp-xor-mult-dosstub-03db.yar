rule TTP_XOR_MULT_DOSStub_03db {
  strings:
    $key_03db = { 57 b3 [2] 23 ab [2] 64 a9 [2] 23 b8 [2] 6d b4 [2] 61 be [2] 76 b5 [2] 6d fb [2] 50 }

  condition:
    any of them
}