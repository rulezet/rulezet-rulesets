rule TTP_XOR_MULT_DOSStub_94e1 {
  strings:
    $key_94e1 = { c0 89 [2] b4 91 [2] f3 93 [2] b4 82 [2] fa 8e [2] f6 84 [2] e1 8f [2] fa c1 [2] c7 }

  condition:
    any of them
}