rule TTP_XOR_MULT_DOSStub_95be {
  strings:
    $key_95be = { c1 d6 [2] b5 ce [2] f2 cc [2] b5 dd [2] fb d1 [2] f7 db [2] e0 d0 [2] fb 9e [2] c6 }

  condition:
    any of them
}