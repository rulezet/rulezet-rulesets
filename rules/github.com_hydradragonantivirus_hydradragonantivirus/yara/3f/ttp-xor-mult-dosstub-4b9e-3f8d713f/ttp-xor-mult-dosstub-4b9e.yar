rule TTP_XOR_MULT_DOSStub_4b9e {
  strings:
    $key_4b9e = { 1f f6 [2] 6b ee [2] 2c ec [2] 6b fd [2] 25 f1 [2] 29 fb [2] 3e f0 [2] 25 be [2] 18 }

  condition:
    any of them
}