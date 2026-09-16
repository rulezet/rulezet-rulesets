rule TTP_XOR_MULT_DOSStub_9592 {
  strings:
    $key_9592 = { c1 fa [2] b5 e2 [2] f2 e0 [2] b5 f1 [2] fb fd [2] f7 f7 [2] e0 fc [2] fb b2 [2] c6 }

  condition:
    any of them
}