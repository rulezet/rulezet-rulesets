rule TTP_XOR_MULT_DOSStub_e3be {
  strings:
    $key_e3be = { b7 d6 [2] c3 ce [2] 84 cc [2] c3 dd [2] 8d d1 [2] 81 db [2] 96 d0 [2] 8d 9e [2] b0 }

  condition:
    any of them
}