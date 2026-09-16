rule TTP_XOR_MULT_DOSStub_a0be {
  strings:
    $key_a0be = { f4 d6 [2] 80 ce [2] c7 cc [2] 80 dd [2] ce d1 [2] c2 db [2] d5 d0 [2] ce 9e [2] f3 }

  condition:
    any of them
}