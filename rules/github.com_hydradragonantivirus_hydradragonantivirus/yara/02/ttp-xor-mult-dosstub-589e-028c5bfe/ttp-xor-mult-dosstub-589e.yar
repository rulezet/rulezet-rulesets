rule TTP_XOR_MULT_DOSStub_589e {
  strings:
    $key_589e = { 0c f6 [2] 78 ee [2] 3f ec [2] 78 fd [2] 36 f1 [2] 3a fb [2] 2d f0 [2] 36 be [2] 0b }

  condition:
    any of them
}