rule TTP_XOR_MULT_DOSStub_95b4 {
  strings:
    $key_95b4 = { c1 dc [2] b5 c4 [2] f2 c6 [2] b5 d7 [2] fb db [2] f7 d1 [2] e0 da [2] fb 94 [2] c6 }

  condition:
    any of them
}