rule TTP_XOR_MULT_DOSStub_96a6 {
  strings:
    $key_96a6 = { c2 ce [2] b6 d6 [2] f1 d4 [2] b6 c5 [2] f8 c9 [2] f4 c3 [2] e3 c8 [2] f8 86 [2] c5 }

  condition:
    any of them
}