rule TTP_XOR_MULT_DOSStub_579e {
  strings:
    $key_579e = { 03 f6 [2] 77 ee [2] 30 ec [2] 77 fd [2] 39 f1 [2] 35 fb [2] 22 f0 [2] 39 be [2] 04 }

  condition:
    any of them
}