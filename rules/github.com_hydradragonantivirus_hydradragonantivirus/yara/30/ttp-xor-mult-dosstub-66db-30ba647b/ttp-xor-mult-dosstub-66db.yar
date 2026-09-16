rule TTP_XOR_MULT_DOSStub_66db {
  strings:
    $key_66db = { 32 b3 [2] 46 ab [2] 01 a9 [2] 46 b8 [2] 08 b4 [2] 04 be [2] 13 b5 [2] 08 fb [2] 35 }

  condition:
    any of them
}