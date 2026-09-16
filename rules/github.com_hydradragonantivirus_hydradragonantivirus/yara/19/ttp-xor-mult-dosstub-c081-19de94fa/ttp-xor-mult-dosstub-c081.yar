rule TTP_XOR_MULT_DOSStub_c081 {
  strings:
    $key_c081 = { 94 e9 [2] e0 f1 [2] a7 f3 [2] e0 e2 [2] ae ee [2] a2 e4 [2] b5 ef [2] ae a1 [2] 93 }

  condition:
    any of them
}