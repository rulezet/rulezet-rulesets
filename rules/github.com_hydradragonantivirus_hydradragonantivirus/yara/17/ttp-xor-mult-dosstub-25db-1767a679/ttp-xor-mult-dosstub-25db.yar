rule TTP_XOR_MULT_DOSStub_25db {
  strings:
    $key_25db = { 71 b3 [2] 05 ab [2] 42 a9 [2] 05 b8 [2] 4b b4 [2] 47 be [2] 50 b5 [2] 4b fb [2] 76 }

  condition:
    any of them
}