rule TTP_XOR_MULT_DOSStub_96b2 {
  strings:
    $key_96b2 = { c2 da [2] b6 c2 [2] f1 c0 [2] b6 d1 [2] f8 dd [2] f4 d7 [2] e3 dc [2] f8 92 [2] c5 }

  condition:
    any of them
}