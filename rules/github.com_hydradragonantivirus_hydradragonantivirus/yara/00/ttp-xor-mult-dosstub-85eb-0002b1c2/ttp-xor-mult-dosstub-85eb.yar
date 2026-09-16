rule TTP_XOR_MULT_DOSStub_85eb {
  strings:
    $key_85eb = { d1 83 [2] a5 9b [2] e2 99 [2] a5 88 [2] eb 84 [2] e7 8e [2] f0 85 [2] eb cb [2] d6 }

  condition:
    any of them
}