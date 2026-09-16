rule TTP_XOR_MULT_DOSStub_10be {
  strings:
    $key_10be = { 44 d6 [2] 30 ce [2] 77 cc [2] 30 dd [2] 7e d1 [2] 72 db [2] 65 d0 [2] 7e 9e [2] 43 }

  condition:
    any of them
}