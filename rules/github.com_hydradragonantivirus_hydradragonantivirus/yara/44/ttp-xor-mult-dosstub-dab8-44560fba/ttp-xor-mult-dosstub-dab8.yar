rule TTP_XOR_MULT_DOSStub_dab8 {
  strings:
    $key_dab8 = { 8e d0 [2] fa c8 [2] bd ca [2] fa db [2] b4 d7 [2] b8 dd [2] af d6 [2] b4 98 [2] 89 }

  condition:
    any of them
}