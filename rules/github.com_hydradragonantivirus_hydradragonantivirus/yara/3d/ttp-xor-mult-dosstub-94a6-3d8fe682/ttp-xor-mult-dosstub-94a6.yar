rule TTP_XOR_MULT_DOSStub_94a6 {
  strings:
    $key_94a6 = { c0 ce [2] b4 d6 [2] f3 d4 [2] b4 c5 [2] fa c9 [2] f6 c3 [2] e1 c8 [2] fa 86 [2] c7 }

  condition:
    any of them
}