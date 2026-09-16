rule TTP_XOR_MULT_DOSStub_9b8b {
  strings:
    $key_9b8b = { cf e3 [2] bb fb [2] fc f9 [2] bb e8 [2] f5 e4 [2] f9 ee [2] ee e5 [2] f5 ab [2] c8 }

  condition:
    any of them
}