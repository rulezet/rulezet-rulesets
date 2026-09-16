rule TTP_XOR_MULT_DOSStub_f7be {
  strings:
    $key_f7be = { a3 d6 [2] d7 ce [2] 90 cc [2] d7 dd [2] 99 d1 [2] 95 db [2] 82 d0 [2] 99 9e [2] a4 }

  condition:
    any of them
}