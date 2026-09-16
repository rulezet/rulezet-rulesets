rule TTP_XOR_MULT_DOSStub_b0be {
  strings:
    $key_b0be = { e4 d6 [2] 90 ce [2] d7 cc [2] 90 dd [2] de d1 [2] d2 db [2] c5 d0 [2] de 9e [2] e3 }

  condition:
    any of them
}