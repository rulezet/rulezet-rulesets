rule TTP_XOR_MULT_DOSStub_dabe {
  strings:
    $key_dabe = { 8e d6 [2] fa ce [2] bd cc [2] fa dd [2] b4 d1 [2] b8 db [2] af d0 [2] b4 9e [2] 89 }

  condition:
    any of them
}