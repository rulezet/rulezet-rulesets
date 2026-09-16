rule TTP_XOR_MULT_DOSStub_9695 {
  strings:
    $key_9695 = { c2 fd [2] b6 e5 [2] f1 e7 [2] b6 f6 [2] f8 fa [2] f4 f0 [2] e3 fb [2] f8 b5 [2] c5 }

  condition:
    any of them
}