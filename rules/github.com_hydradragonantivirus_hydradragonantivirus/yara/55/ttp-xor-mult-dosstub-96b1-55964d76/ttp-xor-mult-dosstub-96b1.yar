rule TTP_XOR_MULT_DOSStub_96b1 {
  strings:
    $key_96b1 = { c2 d9 [2] b6 c1 [2] f1 c3 [2] b6 d2 [2] f8 de [2] f4 d4 [2] e3 df [2] f8 91 [2] c5 }

  condition:
    any of them
}