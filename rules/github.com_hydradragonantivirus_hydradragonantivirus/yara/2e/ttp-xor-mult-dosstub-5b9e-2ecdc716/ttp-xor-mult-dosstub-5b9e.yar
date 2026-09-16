rule TTP_XOR_MULT_DOSStub_5b9e {
  strings:
    $key_5b9e = { 0f f6 [2] 7b ee [2] 3c ec [2] 7b fd [2] 35 f1 [2] 39 fb [2] 2e f0 [2] 35 be [2] 08 }

  condition:
    any of them
}