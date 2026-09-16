rule TTP_XOR_MULT_DOSStub_92fc {
  strings:
    $key_92fc = { c6 94 [2] b2 8c [2] f5 8e [2] b2 9f [2] fc 93 [2] f0 99 [2] e7 92 [2] fc dc [2] c1 }

  condition:
    any of them
}