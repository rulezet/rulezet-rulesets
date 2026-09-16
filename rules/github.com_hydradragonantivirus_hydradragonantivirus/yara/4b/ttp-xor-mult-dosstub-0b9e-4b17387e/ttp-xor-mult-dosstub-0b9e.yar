rule TTP_XOR_MULT_DOSStub_0b9e {
  strings:
    $key_0b9e = { 5f f6 [2] 2b ee [2] 6c ec [2] 2b fd [2] 65 f1 [2] 69 fb [2] 7e f0 [2] 65 be [2] 58 }

  condition:
    any of them
}