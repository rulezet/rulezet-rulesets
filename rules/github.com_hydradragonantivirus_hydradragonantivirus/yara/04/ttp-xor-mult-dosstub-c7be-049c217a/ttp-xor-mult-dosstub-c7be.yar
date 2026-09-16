rule TTP_XOR_MULT_DOSStub_c7be {
  strings:
    $key_c7be = { 93 d6 [2] e7 ce [2] a0 cc [2] e7 dd [2] a9 d1 [2] a5 db [2] b2 d0 [2] a9 9e [2] 94 }

  condition:
    any of them
}