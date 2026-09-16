rule TTP_XOR_MULT_DOSStub_13db {
  strings:
    $key_13db = { 47 b3 [2] 33 ab [2] 74 a9 [2] 33 b8 [2] 7d b4 [2] 71 be [2] 66 b5 [2] 7d fb [2] 40 }

  condition:
    any of them
}