rule TTP_XOR_MULT_DOSStub_86a6 {
  strings:
    $key_86a6 = { d2 ce [2] a6 d6 [2] e1 d4 [2] a6 c5 [2] e8 c9 [2] e4 c3 [2] f3 c8 [2] e8 86 [2] d5 }

  condition:
    any of them
}