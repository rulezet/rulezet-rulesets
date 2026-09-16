rule TTP_XOR_MULT_DOSStub_92b9 {
  strings:
    $key_92b9 = { c6 d1 [2] b2 c9 [2] f5 cb [2] b2 da [2] fc d6 [2] f0 dc [2] e7 d7 [2] fc 99 [2] c1 }

  condition:
    any of them
}