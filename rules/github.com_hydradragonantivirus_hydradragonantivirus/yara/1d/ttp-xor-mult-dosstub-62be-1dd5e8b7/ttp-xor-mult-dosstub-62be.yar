rule TTP_XOR_MULT_DOSStub_62be {
  strings:
    $key_62be = { 36 d6 [2] 42 ce [2] 05 cc [2] 42 dd [2] 0c d1 [2] 00 db [2] 17 d0 [2] 0c 9e [2] 31 }

  condition:
    any of them
}