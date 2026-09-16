rule TTP_XOR_MULT_DOSStub_c6d6 {
  strings:
    $key_c6d6 = { 92 be [2] e6 a6 [2] a1 a4 [2] e6 b5 [2] a8 b9 [2] a4 b3 [2] b3 b8 [2] a8 f6 [2] 95 }

  condition:
    any of them
}