rule TTP_XOR_MULT_DOSStub_9792 {
  strings:
    $key_9792 = { c3 fa [2] b7 e2 [2] f0 e0 [2] b7 f1 [2] f9 fd [2] f5 f7 [2] e2 fc [2] f9 b2 [2] c4 }

  condition:
    any of them
}