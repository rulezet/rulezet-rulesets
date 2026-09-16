rule TTP_XOR_MULT_DOSStub_9494 {
  strings:
    $key_9494 = { c0 fc [2] b4 e4 [2] f3 e6 [2] b4 f7 [2] fa fb [2] f6 f1 [2] e1 fa [2] fa b4 [2] c7 }

  condition:
    any of them
}