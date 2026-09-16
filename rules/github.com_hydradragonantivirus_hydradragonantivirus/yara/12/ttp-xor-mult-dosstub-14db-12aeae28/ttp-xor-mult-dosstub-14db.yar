rule TTP_XOR_MULT_DOSStub_14db {
  strings:
    $key_14db = { 40 b3 [2] 34 ab [2] 73 a9 [2] 34 b8 [2] 7a b4 [2] 76 be [2] 61 b5 [2] 7a fb [2] 47 }

  condition:
    any of them
}