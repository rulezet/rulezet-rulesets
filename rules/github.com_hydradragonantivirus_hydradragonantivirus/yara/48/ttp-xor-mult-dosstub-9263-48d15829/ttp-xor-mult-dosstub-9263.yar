rule TTP_XOR_MULT_DOSStub_9263 {
  strings:
    $key_9263 = { c6 0b [2] b2 13 [2] f5 11 [2] b2 00 [2] fc 0c [2] f0 06 [2] e7 0d [2] fc 43 [2] c1 }

  condition:
    any of them
}