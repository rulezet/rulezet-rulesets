rule TTP_XOR_MULT_DOSStub_87b6 {
  strings:
    $key_87b6 = { d3 de [2] a7 c6 [2] e0 c4 [2] a7 d5 [2] e9 d9 [2] e5 d3 [2] f2 d8 [2] e9 96 [2] d4 }

  condition:
    any of them
}