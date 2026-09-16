rule TTP_XOR_MULT_DOSStub_9394 {
  strings:
    $key_9394 = { c7 fc [2] b3 e4 [2] f4 e6 [2] b3 f7 [2] fd fb [2] f1 f1 [2] e6 fa [2] fd b4 [2] c0 }

  condition:
    any of them
}