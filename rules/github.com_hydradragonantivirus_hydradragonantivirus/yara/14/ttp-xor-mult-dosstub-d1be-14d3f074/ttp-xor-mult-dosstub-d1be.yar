rule TTP_XOR_MULT_DOSStub_d1be {
  strings:
    $key_d1be = { 85 d6 [2] f1 ce [2] b6 cc [2] f1 dd [2] bf d1 [2] b3 db [2] a4 d0 [2] bf 9e [2] 82 }

  condition:
    any of them
}