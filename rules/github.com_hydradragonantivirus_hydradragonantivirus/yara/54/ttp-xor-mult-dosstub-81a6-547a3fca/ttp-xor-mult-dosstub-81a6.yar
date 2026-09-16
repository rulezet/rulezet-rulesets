rule TTP_XOR_MULT_DOSStub_81a6 {
  strings:
    $key_81a6 = { d5 ce [2] a1 d6 [2] e6 d4 [2] a1 c5 [2] ef c9 [2] e3 c3 [2] f4 c8 [2] ef 86 [2] d2 }

  condition:
    any of them
}