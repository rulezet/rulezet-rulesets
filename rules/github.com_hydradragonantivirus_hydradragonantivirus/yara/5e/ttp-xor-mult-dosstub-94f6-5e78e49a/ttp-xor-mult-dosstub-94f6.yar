rule TTP_XOR_MULT_DOSStub_94f6 {
  strings:
    $key_94f6 = { c0 9e [2] b4 86 [2] f3 84 [2] b4 95 [2] fa 99 [2] f6 93 [2] e1 98 [2] fa d6 [2] c7 }

  condition:
    any of them
}