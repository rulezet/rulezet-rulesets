rule TTP_XOR_MULT_DOSStub_59be {
  strings:
    $key_59be = { 0d d6 [2] 79 ce [2] 3e cc [2] 79 dd [2] 37 d1 [2] 3b db [2] 2c d0 [2] 37 9e [2] 0a }

  condition:
    any of them
}