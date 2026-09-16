rule TTP_XOR_MULT_DOSStub_9210 {
  strings:
    $key_9210 = { c6 78 [2] b2 60 [2] f5 62 [2] b2 73 [2] fc 7f [2] f0 75 [2] e7 7e [2] fc 30 [2] c1 }

  condition:
    any of them
}