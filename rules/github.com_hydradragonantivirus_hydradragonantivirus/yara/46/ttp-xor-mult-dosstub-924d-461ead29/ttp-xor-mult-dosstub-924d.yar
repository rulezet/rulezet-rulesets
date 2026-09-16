rule TTP_XOR_MULT_DOSStub_924d {
  strings:
    $key_924d = { c6 25 [2] b2 3d [2] f5 3f [2] b2 2e [2] fc 22 [2] f0 28 [2] e7 23 [2] fc 6d [2] c1 }

  condition:
    any of them
}