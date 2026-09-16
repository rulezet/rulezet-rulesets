rule TTP_XOR_MULT_DOSStub_9250 {
  strings:
    $key_9250 = { c6 38 [2] b2 20 [2] f5 22 [2] b2 33 [2] fc 3f [2] f0 35 [2] e7 3e [2] fc 70 [2] c1 }

  condition:
    any of them
}