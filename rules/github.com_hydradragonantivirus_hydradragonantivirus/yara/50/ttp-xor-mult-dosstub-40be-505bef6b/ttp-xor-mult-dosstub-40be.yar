rule TTP_XOR_MULT_DOSStub_40be {
  strings:
    $key_40be = { 14 d6 [2] 60 ce [2] 27 cc [2] 60 dd [2] 2e d1 [2] 22 db [2] 35 d0 [2] 2e 9e [2] 13 }

  condition:
    any of them
}