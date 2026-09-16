rule TTP_XOR_MULT_DOSStub_a7db {
  strings:
    $key_a7db = { f3 b3 [2] 87 ab [2] c0 a9 [2] 87 b8 [2] c9 b4 [2] c5 be [2] d2 b5 [2] c9 fb [2] f4 }

  condition:
    any of them
}