rule TTP_XOR_MULT_DOSStub_969e {
  strings:
    $key_969e = { c2 f6 [2] b6 ee [2] f1 ec [2] b6 fd [2] f8 f1 [2] f4 fb [2] e3 f0 [2] f8 be [2] c5 }

  condition:
    any of them
}