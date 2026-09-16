rule TTP_XOR_MULT_DOSStub_a1be {
  strings:
    $key_a1be = { f5 d6 [2] 81 ce [2] c6 cc [2] 81 dd [2] cf d1 [2] c3 db [2] d4 d0 [2] cf 9e [2] f2 }

  condition:
    any of them
}