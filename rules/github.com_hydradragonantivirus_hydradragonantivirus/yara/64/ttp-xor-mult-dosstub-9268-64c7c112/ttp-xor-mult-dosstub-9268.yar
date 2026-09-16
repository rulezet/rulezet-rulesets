rule TTP_XOR_MULT_DOSStub_9268 {
  strings:
    $key_9268 = { c6 00 [2] b2 18 [2] f5 1a [2] b2 0b [2] fc 07 [2] f0 0d [2] e7 06 [2] fc 48 [2] c1 }

  condition:
    any of them
}