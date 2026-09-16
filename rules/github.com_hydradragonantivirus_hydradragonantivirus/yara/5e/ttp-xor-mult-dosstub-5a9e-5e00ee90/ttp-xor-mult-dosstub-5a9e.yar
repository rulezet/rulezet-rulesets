rule TTP_XOR_MULT_DOSStub_5a9e {
  strings:
    $key_5a9e = { 0e f6 [2] 7a ee [2] 3d ec [2] 7a fd [2] 34 f1 [2] 38 fb [2] 2f f0 [2] 34 be [2] 09 }

  condition:
    any of them
}