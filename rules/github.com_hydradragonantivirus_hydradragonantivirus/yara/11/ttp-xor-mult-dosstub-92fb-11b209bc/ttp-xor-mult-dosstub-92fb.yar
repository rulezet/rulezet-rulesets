rule TTP_XOR_MULT_DOSStub_92fb {
  strings:
    $key_92fb = { c6 93 [2] b2 8b [2] f5 89 [2] b2 98 [2] fc 94 [2] f0 9e [2] e7 95 [2] fc db [2] c1 }

  condition:
    any of them
}