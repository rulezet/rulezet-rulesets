rule TTP_XOR_MULT_DOSStub_9a96 {
  strings:
    $key_9a96 = { ce fe [2] ba e6 [2] fd e4 [2] ba f5 [2] f4 f9 [2] f8 f3 [2] ef f8 [2] f4 b6 [2] c9 }

  condition:
    any of them
}