rule TTP_XOR_MULT_DOSStub_249e {
  strings:
    $key_249e = { 70 f6 [2] 04 ee [2] 43 ec [2] 04 fd [2] 4a f1 [2] 46 fb [2] 51 f0 [2] 4a be [2] 77 }

  condition:
    any of them
}