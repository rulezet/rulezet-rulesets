rule TTP_XOR_MULT_DOSStub_97a4 {
  strings:
    $key_97a4 = { c3 cc [2] b7 d4 [2] f0 d6 [2] b7 c7 [2] f9 cb [2] f5 c1 [2] e2 ca [2] f9 84 [2] c4 }

  condition:
    any of them
}