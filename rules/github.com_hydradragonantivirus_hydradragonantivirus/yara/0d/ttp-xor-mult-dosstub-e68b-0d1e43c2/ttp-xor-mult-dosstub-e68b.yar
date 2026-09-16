rule TTP_XOR_MULT_DOSStub_e68b {
  strings:
    $key_e68b = { b2 e3 [2] c6 fb [2] 81 f9 [2] c6 e8 [2] 88 e4 [2] 84 ee [2] 93 e5 [2] 88 ab [2] b5 }

  condition:
    any of them
}