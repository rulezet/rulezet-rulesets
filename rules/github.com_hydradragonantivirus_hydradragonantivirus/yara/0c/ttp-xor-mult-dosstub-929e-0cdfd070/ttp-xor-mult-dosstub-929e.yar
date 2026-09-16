rule TTP_XOR_MULT_DOSStub_929e {
  strings:
    $key_929e = { c6 f6 [2] b2 ee [2] f5 ec [2] b2 fd [2] fc f1 [2] f0 fb [2] e7 f0 [2] fc be [2] c1 }

  condition:
    any of them
}