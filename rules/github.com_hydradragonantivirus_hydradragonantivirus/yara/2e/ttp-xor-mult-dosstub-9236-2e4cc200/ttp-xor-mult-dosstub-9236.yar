rule TTP_XOR_MULT_DOSStub_9236 {
  strings:
    $key_9236 = { c6 5e [2] b2 46 [2] f5 44 [2] b2 55 [2] fc 59 [2] f0 53 [2] e7 58 [2] fc 16 [2] c1 }

  condition:
    any of them
}