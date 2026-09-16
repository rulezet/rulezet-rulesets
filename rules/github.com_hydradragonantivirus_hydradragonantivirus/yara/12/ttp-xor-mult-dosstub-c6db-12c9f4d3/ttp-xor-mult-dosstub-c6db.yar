rule TTP_XOR_MULT_DOSStub_c6db {
  strings:
    $key_c6db = { 92 b3 [2] e6 ab [2] a1 a9 [2] e6 b8 [2] a8 b4 [2] a4 be [2] b3 b5 [2] a8 fb [2] 95 }

  condition:
    any of them
}