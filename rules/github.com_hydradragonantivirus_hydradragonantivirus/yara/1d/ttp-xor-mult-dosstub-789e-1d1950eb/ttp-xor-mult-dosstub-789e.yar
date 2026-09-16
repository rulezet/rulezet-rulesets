rule TTP_XOR_MULT_DOSStub_789e {
  strings:
    $key_789e = { 2c f6 [2] 58 ee [2] 1f ec [2] 58 fd [2] 16 f1 [2] 1a fb [2] 0d f0 [2] 16 be [2] 2b }

  condition:
    any of them
}