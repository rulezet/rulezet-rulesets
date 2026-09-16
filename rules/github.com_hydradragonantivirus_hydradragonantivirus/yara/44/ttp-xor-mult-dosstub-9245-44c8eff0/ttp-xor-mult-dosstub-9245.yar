rule TTP_XOR_MULT_DOSStub_9245 {
  strings:
    $key_9245 = { c6 2d [2] b2 35 [2] f5 37 [2] b2 26 [2] fc 2a [2] f0 20 [2] e7 2b [2] fc 65 [2] c1 }

  condition:
    any of them
}