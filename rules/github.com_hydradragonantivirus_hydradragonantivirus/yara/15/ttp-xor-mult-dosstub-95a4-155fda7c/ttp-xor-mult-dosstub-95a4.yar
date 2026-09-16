rule TTP_XOR_MULT_DOSStub_95a4 {
  strings:
    $key_95a4 = { c1 cc [2] b5 d4 [2] f2 d6 [2] b5 c7 [2] fb cb [2] f7 c1 [2] e0 ca [2] fb 84 [2] c6 }

  condition:
    any of them
}