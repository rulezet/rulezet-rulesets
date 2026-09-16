rule TTP_XOR_MULT_DOSStub_4abe {
  strings:
    $key_4abe = { 1e d6 [2] 6a ce [2] 2d cc [2] 6a dd [2] 24 d1 [2] 28 db [2] 3f d0 [2] 24 9e [2] 19 }

  condition:
    any of them
}