rule TTP_XOR_MULT_DOSStub_7b9e {
  strings:
    $key_7b9e = { 2f f6 [2] 5b ee [2] 1c ec [2] 5b fd [2] 15 f1 [2] 19 fb [2] 0e f0 [2] 15 be [2] 28 }

  condition:
    any of them
}