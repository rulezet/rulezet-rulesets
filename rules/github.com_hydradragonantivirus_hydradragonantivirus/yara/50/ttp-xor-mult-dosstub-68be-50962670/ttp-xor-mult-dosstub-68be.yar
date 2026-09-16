rule TTP_XOR_MULT_DOSStub_68be {
  strings:
    $key_68be = { 3c d6 [2] 48 ce [2] 0f cc [2] 48 dd [2] 06 d1 [2] 0a db [2] 1d d0 [2] 06 9e [2] 3b }

  condition:
    any of them
}