rule TTP_XOR_MULT_DOSStub_9292 {
  strings:
    $key_9292 = { c6 fa [2] b2 e2 [2] f5 e0 [2] b2 f1 [2] fc fd [2] f0 f7 [2] e7 fc [2] fc b2 [2] c1 }

  condition:
    any of them
}