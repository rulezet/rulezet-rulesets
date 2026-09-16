rule TTP_XOR_MULT_DOSStub_50be {
  strings:
    $key_50be = { 04 d6 [2] 70 ce [2] 37 cc [2] 70 dd [2] 3e d1 [2] 32 db [2] 25 d0 [2] 3e 9e [2] 03 }

  condition:
    any of them
}