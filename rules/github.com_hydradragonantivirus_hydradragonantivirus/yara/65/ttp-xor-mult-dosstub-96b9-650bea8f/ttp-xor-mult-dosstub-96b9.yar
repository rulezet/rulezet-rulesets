rule TTP_XOR_MULT_DOSStub_96b9 {
  strings:
    $key_96b9 = { c2 d1 [2] b6 c9 [2] f1 cb [2] b6 da [2] f8 d6 [2] f4 dc [2] e3 d7 [2] f8 99 [2] c5 }

  condition:
    any of them
}