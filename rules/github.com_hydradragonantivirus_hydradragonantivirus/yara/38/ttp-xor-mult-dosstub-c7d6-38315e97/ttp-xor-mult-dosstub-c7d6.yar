rule TTP_XOR_MULT_DOSStub_c7d6 {
  strings:
    $key_c7d6 = { 93 be [2] e7 a6 [2] a0 a4 [2] e7 b5 [2] a9 b9 [2] a5 b3 [2] b2 b8 [2] a9 f6 [2] 94 }

  condition:
    any of them
}