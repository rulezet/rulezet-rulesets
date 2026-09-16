rule TTP_XOR_MULT_DOSStub_9249 {
  strings:
    $key_9249 = { c6 21 [2] b2 39 [2] f5 3b [2] b2 2a [2] fc 26 [2] f0 2c [2] e7 27 [2] fc 69 [2] c1 }

  condition:
    any of them
}