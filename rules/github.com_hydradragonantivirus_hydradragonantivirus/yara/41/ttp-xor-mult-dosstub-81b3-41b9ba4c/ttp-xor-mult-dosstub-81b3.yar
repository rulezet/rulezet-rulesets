rule TTP_XOR_MULT_DOSStub_81b3 {
  strings:
    $key_81b3 = { d5 db [2] a1 c3 [2] e6 c1 [2] a1 d0 [2] ef dc [2] e3 d6 [2] f4 dd [2] ef 93 [2] d2 }

  condition:
    any of them
}