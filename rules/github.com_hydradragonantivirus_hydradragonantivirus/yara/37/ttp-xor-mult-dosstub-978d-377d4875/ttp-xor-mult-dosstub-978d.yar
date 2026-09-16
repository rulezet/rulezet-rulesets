rule TTP_XOR_MULT_DOSStub_978d {
  strings:
    $key_978d = { c3 e5 [2] b7 fd [2] f0 ff [2] b7 ee [2] f9 e2 [2] f5 e8 [2] e2 e3 [2] f9 ad [2] c4 }

  condition:
    any of them
}