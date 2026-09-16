rule TTP_XOR_MULT_DOSStub_9a95 {
  strings:
    $key_9a95 = { ce fd [2] ba e5 [2] fd e7 [2] ba f6 [2] f4 fa [2] f8 f0 [2] ef fb [2] f4 b5 [2] c9 }

  condition:
    any of them
}