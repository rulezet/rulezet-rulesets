rule TTP_XOR_MULT_DOSStub_9398 {
  strings:
    $key_9398 = { c7 f0 [2] b3 e8 [2] f4 ea [2] b3 fb [2] fd f7 [2] f1 fd [2] e6 f6 [2] fd b8 [2] c0 }

  condition:
    any of them
}