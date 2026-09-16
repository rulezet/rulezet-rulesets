rule TTP_XOR_MULT_DOSStub_926a {
  strings:
    $key_926a = { c6 02 [2] b2 1a [2] f5 18 [2] b2 09 [2] fc 05 [2] f0 0f [2] e7 04 [2] fc 4a [2] c1 }

  condition:
    any of them
}