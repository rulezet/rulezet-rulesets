rule TTP_XOR_MULT_DOSStub_c7a6 {
  strings:
    $key_c7a6 = { 93 ce [2] e7 d6 [2] a0 d4 [2] e7 c5 [2] a9 c9 [2] a5 c3 [2] b2 c8 [2] a9 86 [2] 94 }

  condition:
    any of them
}