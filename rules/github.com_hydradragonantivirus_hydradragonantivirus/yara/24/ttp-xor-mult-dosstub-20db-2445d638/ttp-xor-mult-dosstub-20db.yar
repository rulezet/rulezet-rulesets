rule TTP_XOR_MULT_DOSStub_20db {
  strings:
    $key_20db = { 74 b3 [2] 00 ab [2] 47 a9 [2] 00 b8 [2] 4e b4 [2] 42 be [2] 55 b5 [2] 4e fb [2] 73 }

  condition:
    any of them
}