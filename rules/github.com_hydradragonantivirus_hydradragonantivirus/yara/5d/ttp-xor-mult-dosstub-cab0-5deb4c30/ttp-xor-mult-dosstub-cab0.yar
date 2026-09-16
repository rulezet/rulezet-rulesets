rule TTP_XOR_MULT_DOSStub_cab0 {
  strings:
    $key_cab0 = { 9e d8 [2] ea c0 [2] ad c2 [2] ea d3 [2] a4 df [2] a8 d5 [2] bf de [2] a4 90 [2] 99 }

  condition:
    any of them
}