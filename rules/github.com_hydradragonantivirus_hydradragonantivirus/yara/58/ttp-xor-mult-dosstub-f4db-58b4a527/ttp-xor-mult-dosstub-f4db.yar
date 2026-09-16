rule TTP_XOR_MULT_DOSStub_f4db {
  strings:
    $key_f4db = { a0 b3 [2] d4 ab [2] 93 a9 [2] d4 b8 [2] 9a b4 [2] 96 be [2] 81 b5 [2] 9a fb [2] a7 }

  condition:
    any of them
}