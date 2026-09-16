rule TTP_XOR_MULT_DOSStub_099e {
  strings:
    $key_099e = { 5d f6 [2] 29 ee [2] 6e ec [2] 29 fd [2] 67 f1 [2] 6b fb [2] 7c f0 [2] 67 be [2] 5a }

  condition:
    any of them
}