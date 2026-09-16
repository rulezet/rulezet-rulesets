rule TTP_XOR_MULT_DOSStub_925e {
  strings:
    $key_925e = { c6 36 [2] b2 2e [2] f5 2c [2] b2 3d [2] fc 31 [2] f0 3b [2] e7 30 [2] fc 7e [2] c1 }

  condition:
    any of them
}