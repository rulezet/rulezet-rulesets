rule TTP_XOR_MULT_DOSStub_95b9 {
  strings:
    $key_95b9 = { c1 d1 [2] b5 c9 [2] f2 cb [2] b5 da [2] fb d6 [2] f7 dc [2] e0 d7 [2] fb 99 [2] c6 }

  condition:
    any of them
}