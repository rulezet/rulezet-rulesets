rule TTP_XOR_MULT_DOSStub_fbbe {
  strings:
    $key_fbbe = { af d6 [2] db ce [2] 9c cc [2] db dd [2] 95 d1 [2] 99 db [2] 8e d0 [2] 95 9e [2] a8 }

  condition:
    any of them
}