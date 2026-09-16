rule TTP_XOR_MULT_DOSStub_9694 {
  strings:
    $key_9694 = { c2 fc [2] b6 e4 [2] f1 e6 [2] b6 f7 [2] f8 fb [2] f4 f1 [2] e3 fa [2] f8 b4 [2] c5 }

  condition:
    any of them
}