rule TTP_XOR_MULT_DOSStub_9243 {
  strings:
    $key_9243 = { c6 2b [2] b2 33 [2] f5 31 [2] b2 20 [2] fc 2c [2] f0 26 [2] e7 2d [2] fc 63 [2] c1 }

  condition:
    any of them
}