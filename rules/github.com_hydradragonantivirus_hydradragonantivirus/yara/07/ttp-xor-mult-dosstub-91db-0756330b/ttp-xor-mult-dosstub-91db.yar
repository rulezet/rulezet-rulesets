rule TTP_XOR_MULT_DOSStub_91db {
  strings:
    $key_91db = { c5 b3 [2] b1 ab [2] f6 a9 [2] b1 b8 [2] ff b4 [2] f3 be [2] e4 b5 [2] ff fb [2] c2 }

  condition:
    any of them
}