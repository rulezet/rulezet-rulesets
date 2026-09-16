rule TTP_XOR_MULT_DOSStub_83db {
  strings:
    $key_83db = { d7 b3 [2] a3 ab [2] e4 a9 [2] a3 b8 [2] ed b4 [2] e1 be [2] f6 b5 [2] ed fb [2] d0 }

  condition:
    any of them
}