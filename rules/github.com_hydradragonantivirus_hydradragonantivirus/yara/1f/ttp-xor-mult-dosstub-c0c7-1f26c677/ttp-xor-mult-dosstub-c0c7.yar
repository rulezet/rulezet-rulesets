rule TTP_XOR_MULT_DOSStub_c0c7 {
  strings:
    $key_c0c7 = { 94 af [2] e0 b7 [2] a7 b5 [2] e0 a4 [2] ae a8 [2] a2 a2 [2] b5 a9 [2] ae e7 [2] 93 }

  condition:
    any of them
}