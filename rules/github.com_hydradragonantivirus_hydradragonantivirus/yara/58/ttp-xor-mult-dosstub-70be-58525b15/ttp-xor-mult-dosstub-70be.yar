rule TTP_XOR_MULT_DOSStub_70be {
  strings:
    $key_70be = { 24 d6 [2] 50 ce [2] 17 cc [2] 50 dd [2] 1e d1 [2] 12 db [2] 05 d0 [2] 1e 9e [2] 23 }

  condition:
    any of them
}