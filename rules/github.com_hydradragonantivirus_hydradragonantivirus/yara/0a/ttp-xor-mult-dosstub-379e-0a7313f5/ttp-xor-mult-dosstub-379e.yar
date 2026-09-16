rule TTP_XOR_MULT_DOSStub_379e {
  strings:
    $key_379e = { 63 f6 [2] 17 ee [2] 50 ec [2] 17 fd [2] 59 f1 [2] 55 fb [2] 42 f0 [2] 59 be [2] 64 }

  condition:
    any of them
}