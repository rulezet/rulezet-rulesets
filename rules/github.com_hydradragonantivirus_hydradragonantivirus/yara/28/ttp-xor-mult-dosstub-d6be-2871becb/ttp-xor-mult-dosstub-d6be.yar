rule TTP_XOR_MULT_DOSStub_d6be {
  strings:
    $key_d6be = { 82 d6 [2] f6 ce [2] b1 cc [2] f6 dd [2] b8 d1 [2] b4 db [2] a3 d0 [2] b8 9e [2] 85 }

  condition:
    any of them
}