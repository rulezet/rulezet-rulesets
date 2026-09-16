rule TTP_XOR_MULT_DOSStub_81b4 {
  strings:
    $key_81b4 = { d5 dc [2] a1 c4 [2] e6 c6 [2] a1 d7 [2] ef db [2] e3 d1 [2] f4 da [2] ef 94 [2] d2 }

  condition:
    any of them
}