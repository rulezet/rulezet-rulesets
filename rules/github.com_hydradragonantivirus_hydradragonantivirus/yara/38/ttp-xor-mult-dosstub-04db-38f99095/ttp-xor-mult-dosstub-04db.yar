rule TTP_XOR_MULT_DOSStub_04db {
  strings:
    $key_04db = { 50 b3 [2] 24 ab [2] 63 a9 [2] 24 b8 [2] 6a b4 [2] 66 be [2] 71 b5 [2] 6a fb [2] 57 }

  condition:
    any of them
}