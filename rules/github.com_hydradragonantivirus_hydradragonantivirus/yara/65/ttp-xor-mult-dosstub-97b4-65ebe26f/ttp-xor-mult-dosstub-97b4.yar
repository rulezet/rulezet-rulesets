rule TTP_XOR_MULT_DOSStub_97b4 {
  strings:
    $key_97b4 = { c3 dc [2] b7 c4 [2] f0 c6 [2] b7 d7 [2] f9 db [2] f5 d1 [2] e2 da [2] f9 94 [2] c4 }

  condition:
    any of them
}