rule TTP_XOR_MULT_DOSStub_788b {
  strings:
    $key_788b = { 2c e3 [2] 58 fb [2] 1f f9 [2] 58 e8 [2] 16 e4 [2] 1a ee [2] 0d e5 [2] 16 ab [2] 2b }

  condition:
    any of them
}