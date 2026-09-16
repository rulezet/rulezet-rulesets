rule TTP_XOR_MULT_DOSStub_ab9e {
  strings:
    $key_ab9e = { ff f6 [2] 8b ee [2] cc ec [2] 8b fd [2] c5 f1 [2] c9 fb [2] de f0 [2] c5 be [2] f8 }

  condition:
    any of them
}