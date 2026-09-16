rule TTP_XOR_MULT_DOSStub_9247 {
  strings:
    $key_9247 = { c6 2f [2] b2 37 [2] f5 35 [2] b2 24 [2] fc 28 [2] f0 22 [2] e7 29 [2] fc 67 [2] c1 }

  condition:
    any of them
}