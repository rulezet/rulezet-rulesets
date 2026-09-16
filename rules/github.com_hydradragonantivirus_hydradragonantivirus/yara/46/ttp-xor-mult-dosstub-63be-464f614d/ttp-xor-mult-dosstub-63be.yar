rule TTP_XOR_MULT_DOSStub_63be {
  strings:
    $key_63be = { 37 d6 [2] 43 ce [2] 04 cc [2] 43 dd [2] 0d d1 [2] 01 db [2] 16 d0 [2] 0d 9e [2] 30 }

  condition:
    any of them
}