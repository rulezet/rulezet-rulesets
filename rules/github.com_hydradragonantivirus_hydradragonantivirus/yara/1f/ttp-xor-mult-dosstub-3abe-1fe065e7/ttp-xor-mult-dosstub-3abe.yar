rule TTP_XOR_MULT_DOSStub_3abe {
  strings:
    $key_3abe = { 6e d6 [2] 1a ce [2] 5d cc [2] 1a dd [2] 54 d1 [2] 58 db [2] 4f d0 [2] 54 9e [2] 69 }

  condition:
    any of them
}