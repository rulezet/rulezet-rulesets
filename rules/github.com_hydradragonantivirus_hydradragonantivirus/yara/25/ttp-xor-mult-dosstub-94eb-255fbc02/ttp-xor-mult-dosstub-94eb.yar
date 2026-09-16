rule TTP_XOR_MULT_DOSStub_94eb {
  strings:
    $key_94eb = { c0 83 [2] b4 9b [2] f3 99 [2] b4 88 [2] fa 84 [2] f6 8e [2] e1 85 [2] fa cb [2] c7 }

  condition:
    any of them
}