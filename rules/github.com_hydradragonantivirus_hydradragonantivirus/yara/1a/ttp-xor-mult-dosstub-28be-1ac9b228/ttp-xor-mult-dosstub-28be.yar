rule TTP_XOR_MULT_DOSStub_28be {
  strings:
    $key_28be = { 7c d6 [2] 08 ce [2] 4f cc [2] 08 dd [2] 46 d1 [2] 4a db [2] 5d d0 [2] 46 9e [2] 7b }

  condition:
    any of them
}