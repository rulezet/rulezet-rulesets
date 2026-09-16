rule TTP_XOR_MULT_DOSStub_779e {
  strings:
    $key_779e = { 23 f6 [2] 57 ee [2] 10 ec [2] 57 fd [2] 19 f1 [2] 15 fb [2] 02 f0 [2] 19 be [2] 24 }

  condition:
    any of them
}