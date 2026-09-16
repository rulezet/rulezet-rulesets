rule TTP_XOR_MULT_DOSStub_029e {
  strings:
    $key_029e = { 56 f6 [2] 22 ee [2] 65 ec [2] 22 fd [2] 6c f1 [2] 60 fb [2] 77 f0 [2] 6c be [2] 51 }

  condition:
    any of them
}