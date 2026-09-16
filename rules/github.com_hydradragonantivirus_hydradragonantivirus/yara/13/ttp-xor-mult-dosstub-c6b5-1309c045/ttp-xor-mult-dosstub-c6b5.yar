rule TTP_XOR_MULT_DOSStub_c6b5 {
  strings:
    $key_c6b5 = { 92 dd [2] e6 c5 [2] a1 c7 [2] e6 d6 [2] a8 da [2] a4 d0 [2] b3 db [2] a8 95 [2] 95 }

  condition:
    any of them
}