rule TTP_XOR_MULT_DOSStub_d5be {
  strings:
    $key_d5be = { 81 d6 [2] f5 ce [2] b2 cc [2] f5 dd [2] bb d1 [2] b7 db [2] a0 d0 [2] bb 9e [2] 86 }

  condition:
    any of them
}