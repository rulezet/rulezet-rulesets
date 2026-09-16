rule TTP_XOR_MULT_DOSStub_96c7 {
  strings:
    $key_96c7 = { c2 af [2] b6 b7 [2] f1 b5 [2] b6 a4 [2] f8 a8 [2] f4 a2 [2] e3 a9 [2] f8 e7 [2] c5 }

  condition:
    any of them
}