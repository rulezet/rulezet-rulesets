rule TTP_XOR_MULT_DOSStub_309e {
  strings:
    $key_309e = { 64 f6 [2] 10 ee [2] 57 ec [2] 10 fd [2] 5e f1 [2] 52 fb [2] 45 f0 [2] 5e be [2] 63 }

  condition:
    any of them
}