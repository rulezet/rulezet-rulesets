rule TTP_XOR_MULT_DOSStub_8b9e {
  strings:
    $key_8b9e = { df f6 [2] ab ee [2] ec ec [2] ab fd [2] e5 f1 [2] e9 fb [2] fe f0 [2] e5 be [2] d8 }

  condition:
    any of them
}