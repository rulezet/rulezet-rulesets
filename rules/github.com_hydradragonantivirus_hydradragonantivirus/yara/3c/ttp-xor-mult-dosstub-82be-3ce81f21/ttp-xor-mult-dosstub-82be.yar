rule TTP_XOR_MULT_DOSStub_82be {
  strings:
    $key_82be = { d6 d6 [2] a2 ce [2] e5 cc [2] a2 dd [2] ec d1 [2] e0 db [2] f7 d0 [2] ec 9e [2] d1 }

  condition:
    any of them
}