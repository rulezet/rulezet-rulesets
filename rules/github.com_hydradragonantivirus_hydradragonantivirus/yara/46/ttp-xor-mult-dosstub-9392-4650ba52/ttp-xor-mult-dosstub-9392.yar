rule TTP_XOR_MULT_DOSStub_9392 {
  strings:
    $key_9392 = { c7 fa [2] b3 e2 [2] f4 e0 [2] b3 f1 [2] fd fd [2] f1 f7 [2] e6 fc [2] fd b2 [2] c0 }

  condition:
    any of them
}