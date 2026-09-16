rule TTP_XOR_MULT_DOSStub_11be {
  strings:
    $key_11be = { 45 d6 [2] 31 ce [2] 76 cc [2] 31 dd [2] 7f d1 [2] 73 db [2] 64 d0 [2] 7f 9e [2] 42 }

  condition:
    any of them
}