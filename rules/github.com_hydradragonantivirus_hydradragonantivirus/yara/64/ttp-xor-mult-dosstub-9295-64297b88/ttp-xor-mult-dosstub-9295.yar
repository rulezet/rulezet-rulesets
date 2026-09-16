rule TTP_XOR_MULT_DOSStub_9295 {
  strings:
    $key_9295 = { c6 fd [2] b2 e5 [2] f5 e7 [2] b2 f6 [2] fc fa [2] f0 f0 [2] e7 fb [2] fc b5 [2] c1 }

  condition:
    any of them
}