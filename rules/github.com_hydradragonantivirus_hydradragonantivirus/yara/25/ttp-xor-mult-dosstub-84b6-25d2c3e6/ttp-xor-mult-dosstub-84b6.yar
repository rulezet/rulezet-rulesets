rule TTP_XOR_MULT_DOSStub_84b6 {
  strings:
    $key_84b6 = { d0 de [2] a4 c6 [2] e3 c4 [2] a4 d5 [2] ea d9 [2] e6 d3 [2] f1 d8 [2] ea 96 [2] d7 }

  condition:
    any of them
}