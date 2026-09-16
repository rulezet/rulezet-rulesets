rule TTP_XOR_MULT_DOSStub_52be {
  strings:
    $key_52be = { 06 d6 [2] 72 ce [2] 35 cc [2] 72 dd [2] 3c d1 [2] 30 db [2] 27 d0 [2] 3c 9e [2] 01 }

  condition:
    any of them
}