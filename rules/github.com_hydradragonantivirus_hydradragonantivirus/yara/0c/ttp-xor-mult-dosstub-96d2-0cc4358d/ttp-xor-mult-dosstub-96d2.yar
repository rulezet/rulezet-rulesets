rule TTP_XOR_MULT_DOSStub_96d2 {
  strings:
    $key_96d2 = { c2 ba [2] b6 a2 [2] f1 a0 [2] b6 b1 [2] f8 bd [2] f4 b7 [2] e3 bc [2] f8 f2 [2] c5 }

  condition:
    any of them
}