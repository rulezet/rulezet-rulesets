rule TTP_XOR_MULT_DOSStub_289e {
  strings:
    $key_289e = { 7c f6 [2] 08 ee [2] 4f ec [2] 08 fd [2] 46 f1 [2] 4a fb [2] 5d f0 [2] 46 be [2] 7b }

  condition:
    any of them
}