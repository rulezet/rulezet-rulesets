rule TTP_XOR_MULT_DOSStub_479e {
  strings:
    $key_479e = { 13 f6 [2] 67 ee [2] 20 ec [2] 67 fd [2] 29 f1 [2] 25 fb [2] 32 f0 [2] 29 be [2] 14 }

  condition:
    any of them
}