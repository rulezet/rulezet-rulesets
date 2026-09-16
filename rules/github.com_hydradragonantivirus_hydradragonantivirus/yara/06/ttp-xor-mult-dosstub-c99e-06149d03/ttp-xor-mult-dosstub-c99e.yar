rule TTP_XOR_MULT_DOSStub_c99e {
  strings:
    $key_c99e = { 9d f6 [2] e9 ee [2] ae ec [2] e9 fd [2] a7 f1 [2] ab fb [2] bc f0 [2] a7 be [2] 9a }

  condition:
    any of them
}