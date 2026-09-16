rule TTP_XOR_MULT_DOSStub_77db {
  strings:
    $key_77db = { 23 b3 [2] 57 ab [2] 10 a9 [2] 57 b8 [2] 19 b4 [2] 15 be [2] 02 b5 [2] 19 fb [2] 24 }

  condition:
    any of them
}