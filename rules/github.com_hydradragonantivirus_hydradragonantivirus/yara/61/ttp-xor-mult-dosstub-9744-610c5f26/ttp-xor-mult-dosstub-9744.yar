rule TTP_XOR_MULT_DOSStub_9744 {
  strings:
    $key_9744 = { c3 2c [2] b7 34 [2] f0 36 [2] b7 27 [2] f9 2b [2] f5 21 [2] e2 2a [2] f9 64 [2] c4 }

  condition:
    any of them
}