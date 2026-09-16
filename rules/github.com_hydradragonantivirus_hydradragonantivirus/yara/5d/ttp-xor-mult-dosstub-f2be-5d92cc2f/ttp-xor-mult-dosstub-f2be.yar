rule TTP_XOR_MULT_DOSStub_f2be {
  strings:
    $key_f2be = { a6 d6 [2] d2 ce [2] 95 cc [2] d2 dd [2] 9c d1 [2] 90 db [2] 87 d0 [2] 9c 9e [2] a1 }

  condition:
    any of them
}