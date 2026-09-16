rule TTP_XOR_MULT_DOSStub_cab1 {
  strings:
    $key_cab1 = { 9e d9 [2] ea c1 [2] ad c3 [2] ea d2 [2] a4 de [2] a8 d4 [2] bf df [2] a4 91 [2] 99 }

  condition:
    any of them
}