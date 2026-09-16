rule TTP_XOR_MULT_DOSStub_cfa9 {
  strings:
    $key_cfa9 = { 9b c1 [2] ef d9 [2] a8 db [2] ef ca [2] a1 c6 [2] ad cc [2] ba c7 [2] a1 89 [2] 9c }

  condition:
    any of them
}