rule TTP_XOR_MULT_DOSStub_9644 {
  strings:
    $key_9644 = { c2 2c [2] b6 34 [2] f1 36 [2] b6 27 [2] f8 2b [2] f4 21 [2] e3 2a [2] f8 64 [2] c5 }

  condition:
    any of them
}