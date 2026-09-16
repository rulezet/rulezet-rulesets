rule TTP_XOR_MULT_DOSStub_1abe {
  strings:
    $key_1abe = { 4e d6 [2] 3a ce [2] 7d cc [2] 3a dd [2] 74 d1 [2] 78 db [2] 6f d0 [2] 74 9e [2] 49 }

  condition:
    any of them
}