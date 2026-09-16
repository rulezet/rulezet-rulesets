rule TTP_XOR_MULT_DOSStub_51be {
  strings:
    $key_51be = { 05 d6 [2] 71 ce [2] 36 cc [2] 71 dd [2] 3f d1 [2] 33 db [2] 24 d0 [2] 3f 9e [2] 02 }

  condition:
    any of them
}