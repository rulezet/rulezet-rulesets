rule TTP_XOR_MULT_DOSStub_cfa0 {
  strings:
    $key_cfa0 = { 9b c8 [2] ef d0 [2] a8 d2 [2] ef c3 [2] a1 cf [2] ad c5 [2] ba ce [2] a1 80 [2] 9c }

  condition:
    any of them
}