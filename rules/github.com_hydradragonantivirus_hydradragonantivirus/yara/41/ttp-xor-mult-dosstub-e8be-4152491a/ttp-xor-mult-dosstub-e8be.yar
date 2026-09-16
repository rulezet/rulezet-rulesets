rule TTP_XOR_MULT_DOSStub_e8be {
  strings:
    $key_e8be = { bc d6 [2] c8 ce [2] 8f cc [2] c8 dd [2] 86 d1 [2] 8a db [2] 9d d0 [2] 86 9e [2] bb }

  condition:
    any of them
}