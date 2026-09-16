rule TTP_XOR_MULT_DOSStub_aa9e {
  strings:
    $key_aa9e = { fe f6 [2] 8a ee [2] cd ec [2] 8a fd [2] c4 f1 [2] c8 fb [2] df f0 [2] c4 be [2] f9 }

  condition:
    any of them
}