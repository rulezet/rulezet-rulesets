rule TTP_XOR_MULT_DOSStub_925c {
  strings:
    $key_925c = { c6 34 [2] b2 2c [2] f5 2e [2] b2 3f [2] fc 33 [2] f0 39 [2] e7 32 [2] fc 7c [2] c1 }

  condition:
    any of them
}