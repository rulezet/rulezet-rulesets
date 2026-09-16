rule TTP_XOR_MULT_DOSStub_94e7 {
  strings:
    $key_94e7 = { c0 8f [2] b4 97 [2] f3 95 [2] b4 84 [2] fa 88 [2] f6 82 [2] e1 89 [2] fa c7 [2] c7 }

  condition:
    any of them
}