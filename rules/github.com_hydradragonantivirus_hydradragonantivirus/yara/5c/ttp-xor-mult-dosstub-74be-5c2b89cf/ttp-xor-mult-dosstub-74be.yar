rule TTP_XOR_MULT_DOSStub_74be {
  strings:
    $key_74be = { 20 d6 [2] 54 ce [2] 13 cc [2] 54 dd [2] 1a d1 [2] 16 db [2] 01 d0 [2] 1a 9e [2] 27 }

  condition:
    any of them
}