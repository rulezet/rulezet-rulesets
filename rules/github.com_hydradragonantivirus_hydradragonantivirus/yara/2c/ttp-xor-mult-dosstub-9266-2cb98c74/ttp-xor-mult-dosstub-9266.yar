rule TTP_XOR_MULT_DOSStub_9266 {
  strings:
    $key_9266 = { c6 0e [2] b2 16 [2] f5 14 [2] b2 05 [2] fc 09 [2] f0 03 [2] e7 08 [2] fc 46 [2] c1 }

  condition:
    any of them
}