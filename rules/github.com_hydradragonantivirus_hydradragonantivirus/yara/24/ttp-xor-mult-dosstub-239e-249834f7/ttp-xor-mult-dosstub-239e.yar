rule TTP_XOR_MULT_DOSStub_239e {
  strings:
    $key_239e = { 77 f6 [2] 03 ee [2] 44 ec [2] 03 fd [2] 4d f1 [2] 41 fb [2] 56 f0 [2] 4d be [2] 70 }

  condition:
    any of them
}