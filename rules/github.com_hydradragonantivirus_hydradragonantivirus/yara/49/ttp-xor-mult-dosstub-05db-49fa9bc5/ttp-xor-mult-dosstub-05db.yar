rule TTP_XOR_MULT_DOSStub_05db {
  strings:
    $key_05db = { 51 b3 [2] 25 ab [2] 62 a9 [2] 25 b8 [2] 6b b4 [2] 67 be [2] 70 b5 [2] 6b fb [2] 56 }

  condition:
    any of them
}