rule TTP_XOR_MULT_DOSStub_00be {
  strings:
    $key_00be = { 54 d6 [2] 20 ce [2] 67 cc [2] 20 dd [2] 6e d1 [2] 62 db [2] 75 d0 [2] 6e 9e [2] 53 }

  condition:
    any of them
}