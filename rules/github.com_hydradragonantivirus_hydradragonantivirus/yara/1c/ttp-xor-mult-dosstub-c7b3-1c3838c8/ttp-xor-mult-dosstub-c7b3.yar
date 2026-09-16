rule TTP_XOR_MULT_DOSStub_c7b3 {
  strings:
    $key_c7b3 = { 93 db [2] e7 c3 [2] a0 c1 [2] e7 d0 [2] a9 dc [2] a5 d6 [2] b2 dd [2] a9 93 [2] 94 }

  condition:
    any of them
}