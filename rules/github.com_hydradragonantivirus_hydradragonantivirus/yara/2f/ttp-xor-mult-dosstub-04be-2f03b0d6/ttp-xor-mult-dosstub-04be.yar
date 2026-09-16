rule TTP_XOR_MULT_DOSStub_04be {
  strings:
    $key_04be = { 50 d6 [2] 24 ce [2] 63 cc [2] 24 dd [2] 6a d1 [2] 66 db [2] 71 d0 [2] 6a 9e [2] 57 }

  condition:
    any of them
}