rule TTP_XOR_MULT_DOSStub_c8be {
  strings:
    $key_c8be = { 9c d6 [2] e8 ce [2] af cc [2] e8 dd [2] a6 d1 [2] aa db [2] bd d0 [2] a6 9e [2] 9b }

  condition:
    any of them
}