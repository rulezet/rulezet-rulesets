rule TTP_XOR_MULT_DOSStub_81b2 {
  strings:
    $key_81b2 = { d5 da [2] a1 c2 [2] e6 c0 [2] a1 d1 [2] ef dd [2] e3 d7 [2] f4 dc [2] ef 92 [2] d2 }

  condition:
    any of them
}