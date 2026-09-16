rule TTP_XOR_MULT_DOSStub_9242 {
  strings:
    $key_9242 = { c6 2a [2] b2 32 [2] f5 30 [2] b2 21 [2] fc 2d [2] f0 27 [2] e7 2c [2] fc 62 [2] c1 }

  condition:
    any of them
}