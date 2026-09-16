rule TTP_XOR_MULT_DOSStub_599e {
  strings:
    $key_599e = { 0d f6 [2] 79 ee [2] 3e ec [2] 79 fd [2] 37 f1 [2] 3b fb [2] 2c f0 [2] 37 be [2] 0a }

  condition:
    any of them
}