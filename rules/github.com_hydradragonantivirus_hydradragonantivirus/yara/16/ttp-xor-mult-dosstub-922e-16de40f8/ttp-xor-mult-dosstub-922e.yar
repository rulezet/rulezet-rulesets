rule TTP_XOR_MULT_DOSStub_922e {
  strings:
    $key_922e = { c6 46 [2] b2 5e [2] f5 5c [2] b2 4d [2] fc 41 [2] f0 4b [2] e7 40 [2] fc 0e [2] c1 }

  condition:
    any of them
}