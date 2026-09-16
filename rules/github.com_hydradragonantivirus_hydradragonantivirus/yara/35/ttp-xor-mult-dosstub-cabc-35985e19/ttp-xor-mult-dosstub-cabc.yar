rule TTP_XOR_MULT_DOSStub_cabc {
  strings:
    $key_cabc = { 9e d4 [2] ea cc [2] ad ce [2] ea df [2] a4 d3 [2] a8 d9 [2] bf d2 [2] a4 9c [2] 99 }

  condition:
    any of them
}