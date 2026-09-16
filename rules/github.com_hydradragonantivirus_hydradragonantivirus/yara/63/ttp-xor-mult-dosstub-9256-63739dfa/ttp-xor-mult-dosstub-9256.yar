rule TTP_XOR_MULT_DOSStub_9256 {
  strings:
    $key_9256 = { c6 3e [2] b2 26 [2] f5 24 [2] b2 35 [2] fc 39 [2] f0 33 [2] e7 38 [2] fc 76 [2] c1 }

  condition:
    any of them
}