rule TTP_XOR_MULT_DOSStub_a6be {
  strings:
    $key_a6be = { f2 d6 [2] 86 ce [2] c1 cc [2] 86 dd [2] c8 d1 [2] c4 db [2] d3 d0 [2] c8 9e [2] f5 }

  condition:
    any of them
}