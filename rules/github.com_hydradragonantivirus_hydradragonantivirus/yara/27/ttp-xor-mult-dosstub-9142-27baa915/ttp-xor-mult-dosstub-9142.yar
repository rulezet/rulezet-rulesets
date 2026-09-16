rule TTP_XOR_MULT_DOSStub_9142 {
  strings:
    $key_9142 = { c5 2a [2] b1 32 [2] f6 30 [2] b1 21 [2] ff 2d [2] f3 27 [2] e4 2c [2] ff 62 [2] c2 }

  condition:
    any of them
}