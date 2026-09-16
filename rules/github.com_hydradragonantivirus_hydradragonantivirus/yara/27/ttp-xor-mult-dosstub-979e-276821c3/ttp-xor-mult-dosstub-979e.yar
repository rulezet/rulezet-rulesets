rule TTP_XOR_MULT_DOSStub_979e {
  strings:
    $key_979e = { c3 f6 [2] b7 ee [2] f0 ec [2] b7 fd [2] f9 f1 [2] f5 fb [2] e2 f0 [2] f9 be [2] c4 }

  condition:
    any of them
}