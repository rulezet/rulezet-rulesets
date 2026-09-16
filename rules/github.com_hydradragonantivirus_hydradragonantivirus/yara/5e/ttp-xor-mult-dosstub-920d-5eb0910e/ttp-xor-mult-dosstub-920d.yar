rule TTP_XOR_MULT_DOSStub_920d {
  strings:
    $key_920d = { c6 65 [2] b2 7d [2] f5 7f [2] b2 6e [2] fc 62 [2] f0 68 [2] e7 63 [2] fc 2d [2] c1 }

  condition:
    any of them
}