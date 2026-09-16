rule TTP_XOR_MULT_DOSStub_41be {
  strings:
    $key_41be = { 15 d6 [2] 61 ce [2] 26 cc [2] 61 dd [2] 2f d1 [2] 23 db [2] 34 d0 [2] 2f 9e [2] 12 }

  condition:
    any of them
}