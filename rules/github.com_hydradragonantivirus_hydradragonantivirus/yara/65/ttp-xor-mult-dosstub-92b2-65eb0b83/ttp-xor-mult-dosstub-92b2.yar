rule TTP_XOR_MULT_DOSStub_92b2 {
  strings:
    $key_92b2 = { c6 da [2] b2 c2 [2] f5 c0 [2] b2 d1 [2] fc dd [2] f0 d7 [2] e7 dc [2] fc 92 [2] c1 }

  condition:
    any of them
}