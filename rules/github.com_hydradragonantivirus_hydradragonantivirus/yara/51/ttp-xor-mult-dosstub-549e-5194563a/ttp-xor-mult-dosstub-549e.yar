rule TTP_XOR_MULT_DOSStub_549e {
  strings:
    $key_549e = { 00 f6 [2] 74 ee [2] 33 ec [2] 74 fd [2] 3a f1 [2] 36 fb [2] 21 f0 [2] 3a be [2] 07 }

  condition:
    any of them
}