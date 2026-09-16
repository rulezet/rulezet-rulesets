rule TTP_XOR_MULT_DOSStub_299e {
  strings:
    $key_299e = { 7d f6 [2] 09 ee [2] 4e ec [2] 09 fd [2] 47 f1 [2] 4b fb [2] 5c f0 [2] 47 be [2] 7a }

  condition:
    any of them
}