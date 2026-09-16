rule TTP_XOR_MULT_DOSStub_e69e {
  strings:
    $key_e69e = { b2 f6 [2] c6 ee [2] 81 ec [2] c6 fd [2] 88 f1 [2] 84 fb [2] 93 f0 [2] 88 be [2] b5 }

  condition:
    any of them
}