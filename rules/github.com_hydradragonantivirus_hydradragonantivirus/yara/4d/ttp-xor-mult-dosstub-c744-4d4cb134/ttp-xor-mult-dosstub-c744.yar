rule TTP_XOR_MULT_DOSStub_c744 {
  strings:
    $key_c744 = { 93 2c [2] e7 34 [2] a0 36 [2] e7 27 [2] a9 2b [2] a5 21 [2] b2 2a [2] a9 64 [2] 94 }

  condition:
    any of them
}