rule TTP_XOR_MULT_DOSStub_cab6 {
  strings:
    $key_cab6 = { 9e de [2] ea c6 [2] ad c4 [2] ea d5 [2] a4 d9 [2] a8 d3 [2] bf d8 [2] a4 96 [2] 99 }

  condition:
    any of them
}