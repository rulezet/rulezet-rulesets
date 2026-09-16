rule TTP_XOR_MULT_DOSStub_cfb3 {
  strings:
    $key_cfb3 = { 9b db [2] ef c3 [2] a8 c1 [2] ef d0 [2] a1 dc [2] ad d6 [2] ba dd [2] a1 93 [2] 9c }

  condition:
    any of them
}