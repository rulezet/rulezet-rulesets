rule TTP_XOR_MULT_DOSStub_c796 {
  strings:
    $key_c796 = { 93 fe [2] e7 e6 [2] a0 e4 [2] e7 f5 [2] a9 f9 [2] a5 f3 [2] b2 f8 [2] a9 b6 [2] 94 }

  condition:
    any of them
}