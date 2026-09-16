rule TTP_XOR_MULT_DOSStub_96e1 {
  strings:
    $key_96e1 = { c2 89 [2] b6 91 [2] f1 93 [2] b6 82 [2] f8 8e [2] f4 84 [2] e3 8f [2] f8 c1 [2] c5 }

  condition:
    any of them
}