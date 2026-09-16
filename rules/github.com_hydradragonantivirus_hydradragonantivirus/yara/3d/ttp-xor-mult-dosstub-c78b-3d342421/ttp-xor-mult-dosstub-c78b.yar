rule TTP_XOR_MULT_DOSStub_c78b {
  strings:
    $key_c78b = { 93 e3 [2] e7 fb [2] a0 f9 [2] e7 e8 [2] a9 e4 [2] a5 ee [2] b2 e5 [2] a9 ab [2] 94 }

  condition:
    any of them
}