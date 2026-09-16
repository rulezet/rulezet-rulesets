rule TTP_XOR_MULT_DOSStub_9275 {
  strings:
    $key_9275 = { c6 1d [2] b2 05 [2] f5 07 [2] b2 16 [2] fc 1a [2] f0 10 [2] e7 1b [2] fc 55 [2] c1 }

  condition:
    any of them
}