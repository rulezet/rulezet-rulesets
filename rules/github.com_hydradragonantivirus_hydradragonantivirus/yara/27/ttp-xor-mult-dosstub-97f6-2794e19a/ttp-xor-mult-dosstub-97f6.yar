rule TTP_XOR_MULT_DOSStub_97f6 {
  strings:
    $key_97f6 = { c3 9e [2] b7 86 [2] f0 84 [2] b7 95 [2] f9 99 [2] f5 93 [2] e2 98 [2] f9 d6 [2] c4 }

  condition:
    any of them
}