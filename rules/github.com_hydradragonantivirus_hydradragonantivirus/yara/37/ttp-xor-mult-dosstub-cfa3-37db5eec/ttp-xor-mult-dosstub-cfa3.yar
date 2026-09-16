rule TTP_XOR_MULT_DOSStub_cfa3 {
  strings:
    $key_cfa3 = { 9b cb [2] ef d3 [2] a8 d1 [2] ef c0 [2] a1 cc [2] ad c6 [2] ba cd [2] a1 83 [2] 9c }

  condition:
    any of them
}