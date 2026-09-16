rule TTP_XOR_MULT_DOSStub_749e {
  strings:
    $key_749e = { 20 f6 [2] 54 ee [2] 13 ec [2] 54 fd [2] 1a f1 [2] 16 fb [2] 01 f0 [2] 1a be [2] 27 }

  condition:
    any of them
}