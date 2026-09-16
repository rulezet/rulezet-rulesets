rule TTP_XOR_MULT_DOSStub_9594 {
  strings:
    $key_9594 = { c1 fc [2] b5 e4 [2] f2 e6 [2] b5 f7 [2] fb fb [2] f7 f1 [2] e0 fa [2] fb b4 [2] c6 }

  condition:
    any of them
}