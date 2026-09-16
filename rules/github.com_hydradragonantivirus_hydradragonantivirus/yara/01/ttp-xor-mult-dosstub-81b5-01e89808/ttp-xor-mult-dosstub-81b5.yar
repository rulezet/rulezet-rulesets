rule TTP_XOR_MULT_DOSStub_81b5 {
  strings:
    $key_81b5 = { d5 dd [2] a1 c5 [2] e6 c7 [2] a1 d6 [2] ef da [2] e3 d0 [2] f4 db [2] ef 95 [2] d2 }

  condition:
    any of them
}