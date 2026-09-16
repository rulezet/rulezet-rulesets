rule TTP_XOR_MULT_DOSStub_9192 {
  strings:
    $key_9192 = { c5 fa [2] b1 e2 [2] f6 e0 [2] b1 f1 [2] ff fd [2] f3 f7 [2] e4 fc [2] ff b2 [2] c2 }

  condition:
    any of them
}