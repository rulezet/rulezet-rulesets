rule TTP_XOR_MULT_DOSStub_47db {
  strings:
    $key_47db = { 13 b3 [2] 67 ab [2] 20 a9 [2] 67 b8 [2] 29 b4 [2] 25 be [2] 32 b5 [2] 29 fb [2] 14 }

  condition:
    any of them
}