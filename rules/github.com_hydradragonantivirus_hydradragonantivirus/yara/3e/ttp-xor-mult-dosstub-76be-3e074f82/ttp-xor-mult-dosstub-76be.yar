rule TTP_XOR_MULT_DOSStub_76be {
  strings:
    $key_76be = { 22 d6 [2] 56 ce [2] 11 cc [2] 56 dd [2] 18 d1 [2] 14 db [2] 03 d0 [2] 18 9e [2] 25 }

  condition:
    any of them
}