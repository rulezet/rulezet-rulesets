rule TTP_XOR_MULT_DOSStub_cfb6 {
  strings:
    $key_cfb6 = { 9b de [2] ef c6 [2] a8 c4 [2] ef d5 [2] a1 d9 [2] ad d3 [2] ba d8 [2] a1 96 [2] 9c }

  condition:
    any of them
}