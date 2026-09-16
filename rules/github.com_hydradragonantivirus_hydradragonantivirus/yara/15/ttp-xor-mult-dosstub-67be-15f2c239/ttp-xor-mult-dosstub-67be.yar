rule TTP_XOR_MULT_DOSStub_67be {
  strings:
    $key_67be = { 33 d6 [2] 47 ce [2] 00 cc [2] 47 dd [2] 09 d1 [2] 05 db [2] 12 d0 [2] 09 9e [2] 34 }

  condition:
    any of them
}