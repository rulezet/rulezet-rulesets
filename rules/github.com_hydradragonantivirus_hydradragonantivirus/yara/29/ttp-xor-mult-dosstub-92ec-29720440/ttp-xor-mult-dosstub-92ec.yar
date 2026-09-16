rule TTP_XOR_MULT_DOSStub_92ec {
  strings:
    $key_92ec = { c6 84 [2] b2 9c [2] f5 9e [2] b2 8f [2] fc 83 [2] f0 89 [2] e7 82 [2] fc cc [2] c1 }

  condition:
    any of them
}