rule TTP_XOR_MULT_DOSStub_2abe {
  strings:
    $key_2abe = { 7e d6 [2] 0a ce [2] 4d cc [2] 0a dd [2] 44 d1 [2] 48 db [2] 5f d0 [2] 44 9e [2] 79 }

  condition:
    any of them
}