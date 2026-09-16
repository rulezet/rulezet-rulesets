rule TTP_XOR_MULT_DOSStub_17be {
  strings:
    $key_17be = { 43 d6 [2] 37 ce [2] 70 cc [2] 37 dd [2] 79 d1 [2] 75 db [2] 62 d0 [2] 79 9e [2] 44 }

  condition:
    any of them
}