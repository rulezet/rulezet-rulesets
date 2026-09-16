rule TTP_XOR_MULT_DOSStub_739e {
  strings:
    $key_739e = { 27 f6 [2] 53 ee [2] 14 ec [2] 53 fd [2] 1d f1 [2] 11 fb [2] 06 f0 [2] 1d be [2] 20 }

  condition:
    any of them
}