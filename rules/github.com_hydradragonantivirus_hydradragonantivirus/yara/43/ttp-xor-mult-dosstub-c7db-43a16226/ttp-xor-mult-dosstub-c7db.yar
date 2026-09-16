rule TTP_XOR_MULT_DOSStub_c7db {
  strings:
    $key_c7db = { 93 b3 [2] e7 ab [2] a0 a9 [2] e7 b8 [2] a9 b4 [2] a5 be [2] b2 b5 [2] a9 fb [2] 94 }

  condition:
    any of them
}