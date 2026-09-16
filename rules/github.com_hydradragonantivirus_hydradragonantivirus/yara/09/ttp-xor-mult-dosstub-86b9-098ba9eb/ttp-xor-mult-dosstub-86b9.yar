rule TTP_XOR_MULT_DOSStub_86b9 {
  strings:
    $key_86b9 = { d2 d1 [2] a6 c9 [2] e1 cb [2] a6 da [2] e8 d6 [2] e4 dc [2] f3 d7 [2] e8 99 [2] d5 }

  condition:
    any of them
}