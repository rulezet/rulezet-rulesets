rule TTP_XOR_MULT_DOSStub_1a9e {
  strings:
    $key_1a9e = { 4e f6 [2] 3a ee [2] 7d ec [2] 3a fd [2] 74 f1 [2] 78 fb [2] 6f f0 [2] 74 be [2] 49 }

  condition:
    any of them
}