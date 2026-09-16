rule TTP_XOR_MULT_DOSStub_99be {
  strings:
    $key_99be = { cd d6 [2] b9 ce [2] fe cc [2] b9 dd [2] f7 d1 [2] fb db [2] ec d0 [2] f7 9e [2] ca }

  condition:
    any of them
}