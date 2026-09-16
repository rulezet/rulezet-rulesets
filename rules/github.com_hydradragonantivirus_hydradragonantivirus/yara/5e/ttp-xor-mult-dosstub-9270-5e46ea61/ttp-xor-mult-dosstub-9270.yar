rule TTP_XOR_MULT_DOSStub_9270 {
  strings:
    $key_9270 = { c6 18 [2] b2 00 [2] f5 02 [2] b2 13 [2] fc 1f [2] f0 15 [2] e7 1e [2] fc 50 [2] c1 }

  condition:
    any of them
}