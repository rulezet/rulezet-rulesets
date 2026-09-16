rule TTP_XOR_MULT_DOSStub_c794 {
  strings:
    $key_c794 = { 93 fc [2] e7 e4 [2] a0 e6 [2] e7 f7 [2] a9 fb [2] a5 f1 [2] b2 fa [2] a9 b4 [2] 94 }

  condition:
    any of them
}