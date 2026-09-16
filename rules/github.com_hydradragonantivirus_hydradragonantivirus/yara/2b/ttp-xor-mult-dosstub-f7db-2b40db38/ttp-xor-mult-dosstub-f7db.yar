rule TTP_XOR_MULT_DOSStub_f7db {
  strings:
    $key_f7db = { a3 b3 [2] d7 ab [2] 90 a9 [2] d7 b8 [2] 99 b4 [2] 95 be [2] 82 b5 [2] 99 fb [2] a4 }

  condition:
    any of them
}