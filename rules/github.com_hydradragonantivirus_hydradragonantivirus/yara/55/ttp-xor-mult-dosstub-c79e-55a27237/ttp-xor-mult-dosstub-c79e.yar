rule TTP_XOR_MULT_DOSStub_c79e {
  strings:
    $key_c79e = { 93 f6 [2] e7 ee [2] a0 ec [2] e7 fd [2] a9 f1 [2] a5 fb [2] b2 f0 [2] a9 be [2] 94 }

  condition:
    any of them
}