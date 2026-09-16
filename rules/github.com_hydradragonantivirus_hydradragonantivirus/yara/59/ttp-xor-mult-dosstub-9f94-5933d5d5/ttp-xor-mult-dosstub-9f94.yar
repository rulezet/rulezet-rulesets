rule TTP_XOR_MULT_DOSStub_9f94 {
  strings:
    $key_9f94 = { cb fc [2] bf e4 [2] f8 e6 [2] bf f7 [2] f1 fb [2] fd f1 [2] ea fa [2] f1 b4 [2] cc }

  condition:
    any of them
}