rule TTP_XOR_MULT_DOSStub_84bb {
  strings:
    $key_84bb = { d0 d3 [2] a4 cb [2] e3 c9 [2] a4 d8 [2] ea d4 [2] e6 de [2] f1 d5 [2] ea 9b [2] d7 }

  condition:
    any of them
}