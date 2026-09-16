rule TTP_XOR_MULT_DOSStub_9244 {
  strings:
    $key_9244 = { c6 2c [2] b2 34 [2] f5 36 [2] b2 27 [2] fc 2b [2] f0 21 [2] e7 2a [2] fc 64 [2] c1 }

  condition:
    any of them
}