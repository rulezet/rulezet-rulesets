rule TTP_XOR_MULT_DOSStub_926e {
  strings:
    $key_926e = { c6 06 [2] b2 1e [2] f5 1c [2] b2 0d [2] fc 01 [2] f0 0b [2] e7 00 [2] fc 4e [2] c1 }

  condition:
    any of them
}