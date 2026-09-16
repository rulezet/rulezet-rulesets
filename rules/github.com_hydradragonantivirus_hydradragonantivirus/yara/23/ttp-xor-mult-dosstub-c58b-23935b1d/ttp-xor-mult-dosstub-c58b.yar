rule TTP_XOR_MULT_DOSStub_c58b {
  strings:
    $key_c58b = { 91 e3 [2] e5 fb [2] a2 f9 [2] e5 e8 [2] ab e4 [2] a7 ee [2] b0 e5 [2] ab ab [2] 96 }

  condition:
    any of them
}