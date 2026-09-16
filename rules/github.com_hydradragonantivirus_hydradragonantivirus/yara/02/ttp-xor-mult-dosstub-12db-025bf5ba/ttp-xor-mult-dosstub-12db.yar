rule TTP_XOR_MULT_DOSStub_12db {
  strings:
    $key_12db = { 46 b3 [2] 32 ab [2] 75 a9 [2] 32 b8 [2] 7c b4 [2] 70 be [2] 67 b5 [2] 7c fb [2] 41 }

  condition:
    any of them
}