rule TTP_XOR_MULT_DOSStub_40db {
  strings:
    $key_40db = { 14 b3 [2] 60 ab [2] 27 a9 [2] 60 b8 [2] 2e b4 [2] 22 be [2] 35 b5 [2] 2e fb [2] 13 }

  condition:
    any of them
}