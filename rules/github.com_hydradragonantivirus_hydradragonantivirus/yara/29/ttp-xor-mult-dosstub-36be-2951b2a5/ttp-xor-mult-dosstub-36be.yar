rule TTP_XOR_MULT_DOSStub_36be {
  strings:
    $key_36be = { 62 d6 [2] 16 ce [2] 51 cc [2] 16 dd [2] 58 d1 [2] 54 db [2] 43 d0 [2] 58 9e [2] 65 }

  condition:
    any of them
}