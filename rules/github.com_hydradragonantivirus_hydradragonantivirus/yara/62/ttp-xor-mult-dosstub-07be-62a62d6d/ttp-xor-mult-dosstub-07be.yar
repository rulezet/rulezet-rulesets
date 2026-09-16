rule TTP_XOR_MULT_DOSStub_07be {
  strings:
    $key_07be = { 53 d6 [2] 27 ce [2] 60 cc [2] 27 dd [2] 69 d1 [2] 65 db [2] 72 d0 [2] 69 9e [2] 54 }

  condition:
    any of them
}