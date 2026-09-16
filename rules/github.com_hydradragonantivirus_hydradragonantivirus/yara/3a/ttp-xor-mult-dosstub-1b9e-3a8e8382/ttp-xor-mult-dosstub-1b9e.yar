rule TTP_XOR_MULT_DOSStub_1b9e {
  strings:
    $key_1b9e = { 4f f6 [2] 3b ee [2] 7c ec [2] 3b fd [2] 75 f1 [2] 79 fb [2] 6e f0 [2] 75 be [2] 48 }

  condition:
    any of them
}