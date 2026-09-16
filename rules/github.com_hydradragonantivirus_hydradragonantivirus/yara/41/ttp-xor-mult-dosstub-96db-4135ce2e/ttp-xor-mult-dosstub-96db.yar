rule TTP_XOR_MULT_DOSStub_96db {
  strings:
    $key_96db = { c2 b3 [2] b6 ab [2] f1 a9 [2] b6 b8 [2] f8 b4 [2] f4 be [2] e3 b5 [2] f8 fb [2] c5 }

  condition:
    any of them
}