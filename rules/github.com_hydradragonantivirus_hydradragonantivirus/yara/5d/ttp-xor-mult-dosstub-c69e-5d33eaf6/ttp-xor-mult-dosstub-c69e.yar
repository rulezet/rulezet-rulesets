rule TTP_XOR_MULT_DOSStub_c69e {
  strings:
    $key_c69e = { 92 f6 [2] e6 ee [2] a1 ec [2] e6 fd [2] a8 f1 [2] a4 fb [2] b3 f0 [2] a8 be [2] 95 }

  condition:
    any of them
}