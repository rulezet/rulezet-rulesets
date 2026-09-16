rule TTP_XOR_MULT_DOSStub_c1b8 {
  strings:
    $key_c1b8 = { 95 d0 [2] e1 c8 [2] a6 ca [2] e1 db [2] af d7 [2] a3 dd [2] b4 d6 [2] af 98 [2] 92 }

  condition:
    any of them
}