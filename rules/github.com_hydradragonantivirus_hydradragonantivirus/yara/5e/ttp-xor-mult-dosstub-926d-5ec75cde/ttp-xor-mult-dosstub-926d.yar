rule TTP_XOR_MULT_DOSStub_926d {
  strings:
    $key_926d = { c6 05 [2] b2 1d [2] f5 1f [2] b2 0e [2] fc 02 [2] f0 08 [2] e7 03 [2] fc 4d [2] c1 }

  condition:
    any of them
}