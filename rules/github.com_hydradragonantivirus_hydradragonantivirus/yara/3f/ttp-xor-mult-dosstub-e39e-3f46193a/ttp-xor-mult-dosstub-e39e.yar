rule TTP_XOR_MULT_DOSStub_e39e {
  strings:
    $key_e39e = { b7 f6 [2] c3 ee [2] 84 ec [2] c3 fd [2] 8d f1 [2] 81 fb [2] 96 f0 [2] 8d be [2] b0 }

  condition:
    any of them
}