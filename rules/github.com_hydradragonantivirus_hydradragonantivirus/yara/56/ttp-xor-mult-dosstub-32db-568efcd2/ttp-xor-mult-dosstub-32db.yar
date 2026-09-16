rule TTP_XOR_MULT_DOSStub_32db {
  strings:
    $key_32db = { 66 b3 [2] 12 ab [2] 55 a9 [2] 12 b8 [2] 5c b4 [2] 50 be [2] 47 b5 [2] 5c fb [2] 61 }

  condition:
    any of them
}