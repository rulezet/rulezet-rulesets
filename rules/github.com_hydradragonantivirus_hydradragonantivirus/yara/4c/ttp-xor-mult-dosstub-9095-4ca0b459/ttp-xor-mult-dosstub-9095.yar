rule TTP_XOR_MULT_DOSStub_9095 {
  strings:
    $key_9095 = { c4 fd [2] b0 e5 [2] f7 e7 [2] b0 f6 [2] fe fa [2] f2 f0 [2] e5 fb [2] fe b5 [2] c3 }

  condition:
    any of them
}