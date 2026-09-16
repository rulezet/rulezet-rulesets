rule TTP_XOR_MULT_DOSStub_67db {
  strings:
    $key_67db = { 33 b3 [2] 47 ab [2] 00 a9 [2] 47 b8 [2] 09 b4 [2] 05 be [2] 12 b5 [2] 09 fb [2] 34 }

  condition:
    any of them
}