rule TTP_XOR_MULT_DOSStub_56be {
  strings:
    $key_56be = { 02 d6 [2] 76 ce [2] 31 cc [2] 76 dd [2] 38 d1 [2] 34 db [2] 23 d0 [2] 38 9e [2] 05 }

  condition:
    any of them
}