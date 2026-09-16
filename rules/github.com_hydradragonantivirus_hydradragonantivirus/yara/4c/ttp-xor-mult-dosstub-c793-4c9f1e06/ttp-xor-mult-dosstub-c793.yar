rule TTP_XOR_MULT_DOSStub_c793 {
  strings:
    $key_c793 = { 93 fb [2] e7 e3 [2] a0 e1 [2] e7 f0 [2] a9 fc [2] a5 f6 [2] b2 fd [2] a9 b3 [2] 94 }

  condition:
    any of them
}