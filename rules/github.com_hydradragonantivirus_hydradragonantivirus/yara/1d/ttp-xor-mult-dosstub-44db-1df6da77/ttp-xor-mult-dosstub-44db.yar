rule TTP_XOR_MULT_DOSStub_44db {
  strings:
    $key_44db = { 10 b3 [2] 64 ab [2] 23 a9 [2] 64 b8 [2] 2a b4 [2] 26 be [2] 31 b5 [2] 2a fb [2] 17 }

  condition:
    any of them
}