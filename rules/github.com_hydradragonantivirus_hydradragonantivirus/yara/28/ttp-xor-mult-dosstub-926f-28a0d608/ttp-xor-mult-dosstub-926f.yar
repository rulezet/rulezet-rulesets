rule TTP_XOR_MULT_DOSStub_926f {
  strings:
    $key_926f = { c6 07 [2] b2 1f [2] f5 1d [2] b2 0c [2] fc 00 [2] f0 0a [2] e7 01 [2] fc 4f [2] c1 }

  condition:
    any of them
}