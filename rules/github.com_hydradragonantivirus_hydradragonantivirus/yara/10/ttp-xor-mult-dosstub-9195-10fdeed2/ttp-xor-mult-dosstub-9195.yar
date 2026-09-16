rule TTP_XOR_MULT_DOSStub_9195 {
  strings:
    $key_9195 = { c5 fd [2] b1 e5 [2] f6 e7 [2] b1 f6 [2] ff fa [2] f3 f0 [2] e4 fb [2] ff b5 [2] c2 }

  condition:
    any of them
}