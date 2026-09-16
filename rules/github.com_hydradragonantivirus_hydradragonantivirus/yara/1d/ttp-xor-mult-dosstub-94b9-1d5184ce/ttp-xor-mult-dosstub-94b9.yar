rule TTP_XOR_MULT_DOSStub_94b9 {
  strings:
    $key_94b9 = { c0 d1 [2] b4 c9 [2] f3 cb [2] b4 da [2] fa d6 [2] f6 dc [2] e1 d7 [2] fa 99 [2] c7 }

  condition:
    any of them
}