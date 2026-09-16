rule TTP_XOR_MULT_DOSStub_469e {
  strings:
    $key_469e = { 12 f6 [2] 66 ee [2] 21 ec [2] 66 fd [2] 28 f1 [2] 24 fb [2] 33 f0 [2] 28 be [2] 15 }

  condition:
    any of them
}