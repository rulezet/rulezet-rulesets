rule TTP_XOR_MULT_DOSStub_cab4 {
  strings:
    $key_cab4 = { 9e dc [2] ea c4 [2] ad c6 [2] ea d7 [2] a4 db [2] a8 d1 [2] bf da [2] a4 94 [2] 99 }

  condition:
    any of them
}