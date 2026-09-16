rule TTP_XOR_MULT_DOSStub_97be {
  strings:
    $key_97be = { c3 d6 [2] b7 ce [2] f0 cc [2] b7 dd [2] f9 d1 [2] f5 db [2] e2 d0 [2] f9 9e [2] c4 }

  condition:
    any of them
}