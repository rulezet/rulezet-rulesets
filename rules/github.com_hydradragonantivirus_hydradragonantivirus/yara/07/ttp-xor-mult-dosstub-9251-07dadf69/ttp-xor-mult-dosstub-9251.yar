rule TTP_XOR_MULT_DOSStub_9251 {
  strings:
    $key_9251 = { c6 39 [2] b2 21 [2] f5 23 [2] b2 32 [2] fc 3e [2] f0 34 [2] e7 3f [2] fc 71 [2] c1 }

  condition:
    any of them
}