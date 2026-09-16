rule TTP_XOR_MULT_DOSStub_81b9 {
  strings:
    $key_81b9 = { d5 d1 [2] a1 c9 [2] e6 cb [2] a1 da [2] ef d6 [2] e3 dc [2] f4 d7 [2] ef 99 [2] d2 }

  condition:
    any of them
}