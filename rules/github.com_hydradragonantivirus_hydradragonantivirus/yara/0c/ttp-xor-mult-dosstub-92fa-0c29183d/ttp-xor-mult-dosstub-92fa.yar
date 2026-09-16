rule TTP_XOR_MULT_DOSStub_92fa {
  strings:
    $key_92fa = { c6 92 [2] b2 8a [2] f5 88 [2] b2 99 [2] fc 95 [2] f0 9f [2] e7 94 [2] fc da [2] c1 }

  condition:
    any of them
}