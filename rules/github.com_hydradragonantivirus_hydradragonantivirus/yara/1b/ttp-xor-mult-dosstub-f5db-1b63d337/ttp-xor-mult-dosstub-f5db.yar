rule TTP_XOR_MULT_DOSStub_f5db {
  strings:
    $key_f5db = { a1 b3 [2] d5 ab [2] 92 a9 [2] d5 b8 [2] 9b b4 [2] 97 be [2] 80 b5 [2] 9b fb [2] a6 }

  condition:
    any of them
}