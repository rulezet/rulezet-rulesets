rule TTP_XOR_MULT_DOSStub_81bb {
  strings:
    $key_81bb = { d5 d3 [2] a1 cb [2] e6 c9 [2] a1 d8 [2] ef d4 [2] e3 de [2] f4 d5 [2] ef 9b [2] d2 }

  condition:
    any of them
}