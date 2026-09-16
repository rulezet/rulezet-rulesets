rule TTP_XOR_MULT_DOSStub_978b {
  strings:
    $key_978b = { c3 e3 [2] b7 fb [2] f0 f9 [2] b7 e8 [2] f9 e4 [2] f5 ee [2] e2 e5 [2] f9 ab [2] c4 }

  condition:
    any of them
}