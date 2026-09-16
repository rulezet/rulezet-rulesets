rule TTP_XOR_MULT_DOSStub_73db {
  strings:
    $key_73db = { 27 b3 [2] 53 ab [2] 14 a9 [2] 53 b8 [2] 1d b4 [2] 11 be [2] 06 b5 [2] 1d fb [2] 20 }

  condition:
    any of them
}