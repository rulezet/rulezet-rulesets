rule TTP_XOR_MULT_DOSStub_81a4 {
  strings:
    $key_81a4 = { d5 cc [2] a1 d4 [2] e6 d6 [2] a1 c7 [2] ef cb [2] e3 c1 [2] f4 ca [2] ef 84 [2] d2 }

  condition:
    any of them
}