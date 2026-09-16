rule TTP_XOR_MULT_DOSStub_139e {
  strings:
    $key_139e = { 47 f6 [2] 33 ee [2] 74 ec [2] 33 fd [2] 7d f1 [2] 71 fb [2] 66 f0 [2] 7d be [2] 40 }

  condition:
    any of them
}