rule TTP_XOR_MULT_DOSStub_51db {
  strings:
    $key_51db = { 05 b3 [2] 71 ab [2] 36 a9 [2] 71 b8 [2] 3f b4 [2] 33 be [2] 24 b5 [2] 3f fb [2] 02 }

  condition:
    any of them
}