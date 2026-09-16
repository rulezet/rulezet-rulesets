rule TTP_XOR_MULT_DOSStub_629e {
  strings:
    $key_629e = { 36 f6 [2] 42 ee [2] 05 ec [2] 42 fd [2] 0c f1 [2] 00 fb [2] 17 f0 [2] 0c be [2] 31 }

  condition:
    any of them
}