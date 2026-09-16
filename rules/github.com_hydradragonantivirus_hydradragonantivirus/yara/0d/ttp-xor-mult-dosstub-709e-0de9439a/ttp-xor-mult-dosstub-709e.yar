rule TTP_XOR_MULT_DOSStub_709e {
  strings:
    $key_709e = { 24 f6 [2] 50 ee [2] 17 ec [2] 50 fd [2] 1e f1 [2] 12 fb [2] 05 f0 [2] 1e be [2] 23 }

  condition:
    any of them
}