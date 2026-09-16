rule TTP_XOR_MULT_DOSStub_079e {
  strings:
    $key_079e = { 53 f6 [2] 27 ee [2] 60 ec [2] 27 fd [2] 69 f1 [2] 65 fb [2] 72 f0 [2] 69 be [2] 54 }

  condition:
    any of them
}