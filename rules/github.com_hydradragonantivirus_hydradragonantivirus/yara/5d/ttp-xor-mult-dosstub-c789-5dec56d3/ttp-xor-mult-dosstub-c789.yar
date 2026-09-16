rule TTP_XOR_MULT_DOSStub_c789 {
  strings:
    $key_c789 = { 93 e1 [2] e7 f9 [2] a0 fb [2] e7 ea [2] a9 e6 [2] a5 ec [2] b2 e7 [2] a9 a9 [2] 94 }

  condition:
    any of them
}