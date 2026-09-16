rule TTP_XOR_MULT_DOSStub_689e {
  strings:
    $key_689e = { 3c f6 [2] 48 ee [2] 0f ec [2] 48 fd [2] 06 f1 [2] 0a fb [2] 1d f0 [2] 06 be [2] 3b }

  condition:
    any of them
}