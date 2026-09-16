rule TTP_XOR_MULT_DOSStub_e29e {
  strings:
    $key_e29e = { b6 f6 [2] c2 ee [2] 85 ec [2] c2 fd [2] 8c f1 [2] 80 fb [2] 97 f0 [2] 8c be [2] b1 }

  condition:
    any of them
}