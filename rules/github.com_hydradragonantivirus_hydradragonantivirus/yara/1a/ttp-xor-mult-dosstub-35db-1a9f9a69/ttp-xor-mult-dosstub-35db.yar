rule TTP_XOR_MULT_DOSStub_35db {
  strings:
    $key_35db = { 61 b3 [2] 15 ab [2] 52 a9 [2] 15 b8 [2] 5b b4 [2] 57 be [2] 40 b5 [2] 5b fb [2] 66 }

  condition:
    any of them
}