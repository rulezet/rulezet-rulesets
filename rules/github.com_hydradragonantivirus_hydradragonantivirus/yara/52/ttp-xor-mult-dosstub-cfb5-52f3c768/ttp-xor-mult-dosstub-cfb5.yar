rule TTP_XOR_MULT_DOSStub_cfb5 {
  strings:
    $key_cfb5 = { 9b dd [2] ef c5 [2] a8 c7 [2] ef d6 [2] a1 da [2] ad d0 [2] ba db [2] a1 95 [2] 9c }

  condition:
    any of them
}