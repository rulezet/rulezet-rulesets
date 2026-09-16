rule TTP_XOR_MULT_DOSStub_a7be {
  strings:
    $key_a7be = { f3 d6 [2] 87 ce [2] c0 cc [2] 87 dd [2] c9 d1 [2] c5 db [2] d2 d0 [2] c9 9e [2] f4 }

  condition:
    any of them
}