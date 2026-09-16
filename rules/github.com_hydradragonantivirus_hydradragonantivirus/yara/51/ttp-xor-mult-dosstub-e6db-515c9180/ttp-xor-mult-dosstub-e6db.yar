rule TTP_XOR_MULT_DOSStub_e6db {
  strings:
    $key_e6db = { b2 b3 [2] c6 ab [2] 81 a9 [2] c6 b8 [2] 88 b4 [2] 84 be [2] 93 b5 [2] 88 fb [2] b5 }

  condition:
    any of them
}