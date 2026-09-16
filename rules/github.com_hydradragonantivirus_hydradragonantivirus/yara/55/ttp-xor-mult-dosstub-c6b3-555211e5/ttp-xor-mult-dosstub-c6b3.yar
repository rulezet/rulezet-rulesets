rule TTP_XOR_MULT_DOSStub_c6b3 {
  strings:
    $key_c6b3 = { 92 db [2] e6 c3 [2] a1 c1 [2] e6 d0 [2] a8 dc [2] a4 d6 [2] b3 dd [2] a8 93 [2] 95 }

  condition:
    any of them
}