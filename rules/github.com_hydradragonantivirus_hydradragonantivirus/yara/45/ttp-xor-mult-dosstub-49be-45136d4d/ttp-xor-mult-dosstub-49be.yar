rule TTP_XOR_MULT_DOSStub_49be {
  strings:
    $key_49be = { 1d d6 [2] 69 ce [2] 2e cc [2] 69 dd [2] 27 d1 [2] 2b db [2] 3c d0 [2] 27 9e [2] 1a }

  condition:
    any of them
}