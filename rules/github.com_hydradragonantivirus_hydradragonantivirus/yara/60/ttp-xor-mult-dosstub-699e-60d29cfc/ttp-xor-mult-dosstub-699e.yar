rule TTP_XOR_MULT_DOSStub_699e {
  strings:
    $key_699e = { 3d f6 [2] 49 ee [2] 0e ec [2] 49 fd [2] 07 f1 [2] 0b fb [2] 1c f0 [2] 07 be [2] 3a }

  condition:
    any of them
}