rule TTP_XOR_MULT_DOSStub_9240 {
  strings:
    $key_9240 = { c6 28 [2] b2 30 [2] f5 32 [2] b2 23 [2] fc 2f [2] f0 25 [2] e7 2e [2] fc 60 [2] c1 }

  condition:
    any of them
}