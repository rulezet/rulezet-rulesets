rule TTP_XOR_MULT_DOSStub_109e {
  strings:
    $key_109e = { 44 f6 [2] 30 ee [2] 77 ec [2] 30 fd [2] 7e f1 [2] 72 fb [2] 65 f0 [2] 7e be [2] 43 }

  condition:
    any of them
}