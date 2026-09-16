rule TTP_XOR_MULT_DOSStub_639e {
  strings:
    $key_639e = { 37 f6 [2] 43 ee [2] 04 ec [2] 43 fd [2] 0d f1 [2] 01 fb [2] 16 f0 [2] 0d be [2] 30 }

  condition:
    any of them
}