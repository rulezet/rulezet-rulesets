rule TTP_XOR_MULT_DOSStub_92eb {
  strings:
    $key_92eb = { c6 83 [2] b2 9b [2] f5 99 [2] b2 88 [2] fc 84 [2] f0 8e [2] e7 85 [2] fc cb [2] c1 }

  condition:
    any of them
}