rule TTP_XOR_MULT_DOSStub_83be {
  strings:
    $key_83be = { d7 d6 [2] a3 ce [2] e4 cc [2] a3 dd [2] ed d1 [2] e1 db [2] f6 d0 [2] ed 9e [2] d0 }

  condition:
    any of them
}