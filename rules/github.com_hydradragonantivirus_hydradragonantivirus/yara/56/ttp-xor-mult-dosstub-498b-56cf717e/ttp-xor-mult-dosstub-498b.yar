rule TTP_XOR_MULT_DOSStub_498b {
  strings:
    $key_498b = { 1d e3 [2] 69 fb [2] 2e f9 [2] 69 e8 [2] 27 e4 [2] 2b ee [2] 3c e5 [2] 27 ab [2] 1a }

  condition:
    any of them
}