rule TTP_XOR_MULT_DOSStub_97b9 {
  strings:
    $key_97b9 = { c3 d1 [2] b7 c9 [2] f0 cb [2] b7 da [2] f9 d6 [2] f5 dc [2] e2 d7 [2] f9 99 [2] c4 }

  condition:
    any of them
}