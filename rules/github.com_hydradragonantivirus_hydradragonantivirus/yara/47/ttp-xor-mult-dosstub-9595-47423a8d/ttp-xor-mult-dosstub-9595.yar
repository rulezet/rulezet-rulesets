rule TTP_XOR_MULT_DOSStub_9595 {
  strings:
    $key_9595 = { c1 fd [2] b5 e5 [2] f2 e7 [2] b5 f6 [2] fb fa [2] f7 f0 [2] e0 fb [2] fb b5 [2] c6 }

  condition:
    any of them
}