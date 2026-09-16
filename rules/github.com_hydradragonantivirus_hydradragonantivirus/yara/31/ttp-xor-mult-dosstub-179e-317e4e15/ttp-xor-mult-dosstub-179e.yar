rule TTP_XOR_MULT_DOSStub_179e {
  strings:
    $key_179e = { 43 f6 [2] 37 ee [2] 70 ec [2] 37 fd [2] 79 f1 [2] 75 fb [2] 62 f0 [2] 79 be [2] 44 }

  condition:
    any of them
}