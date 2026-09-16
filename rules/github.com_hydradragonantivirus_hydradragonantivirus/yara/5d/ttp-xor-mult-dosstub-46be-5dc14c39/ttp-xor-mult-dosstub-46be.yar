rule TTP_XOR_MULT_DOSStub_46be {
  strings:
    $key_46be = { 12 d6 [2] 66 ce [2] 21 cc [2] 66 dd [2] 28 d1 [2] 24 db [2] 33 d0 [2] 28 9e [2] 15 }

  condition:
    any of them
}