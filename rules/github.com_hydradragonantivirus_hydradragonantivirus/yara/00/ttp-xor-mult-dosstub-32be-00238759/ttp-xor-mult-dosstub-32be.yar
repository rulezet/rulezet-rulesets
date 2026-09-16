rule TTP_XOR_MULT_DOSStub_32be {
  strings:
    $key_32be = { 66 d6 [2] 12 ce [2] 55 cc [2] 12 dd [2] 5c d1 [2] 50 db [2] 47 d0 [2] 5c 9e [2] 61 }

  condition:
    any of them
}