rule TTP_XOR_MULT_DOSStub_c1b5 {
  strings:
    $key_c1b5 = { 95 dd [2] e1 c5 [2] a6 c7 [2] e1 d6 [2] af da [2] a3 d0 [2] b4 db [2] af 95 [2] 92 }

  condition:
    any of them
}