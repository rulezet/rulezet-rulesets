rule TTP_XOR_MULT_DOSStub_349e {
  strings:
    $key_349e = { 60 f6 [2] 14 ee [2] 53 ec [2] 14 fd [2] 5a f1 [2] 56 fb [2] 41 f0 [2] 5a be [2] 67 }

  condition:
    any of them
}