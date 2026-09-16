rule TTP_XOR_MULT_DOSStub_d8be {
  strings:
    $key_d8be = { 8c d6 [2] f8 ce [2] bf cc [2] f8 dd [2] b6 d1 [2] ba db [2] ad d0 [2] b6 9e [2] 8b }

  condition:
    any of them
}