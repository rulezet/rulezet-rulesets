rule TTP_XOR_MULT_DOSStub_81b1 {
  strings:
    $key_81b1 = { d5 d9 [2] a1 c1 [2] e6 c3 [2] a1 d2 [2] ef de [2] e3 d4 [2] f4 df [2] ef 91 [2] d2 }

  condition:
    any of them
}