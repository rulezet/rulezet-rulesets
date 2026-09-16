rule TTP_XOR_MULT_DOSStub_60be {
  strings:
    $key_60be = { 34 d6 [2] 40 ce [2] 07 cc [2] 40 dd [2] 0e d1 [2] 02 db [2] 15 d0 [2] 0e 9e [2] 33 }

  condition:
    any of them
}