rule TTP_XOR_MULT_DOSStub_089e {
  strings:
    $key_089e = { 5c f6 [2] 28 ee [2] 6f ec [2] 28 fd [2] 66 f1 [2] 6a fb [2] 7d f0 [2] 66 be [2] 5b }

  condition:
    any of them
}