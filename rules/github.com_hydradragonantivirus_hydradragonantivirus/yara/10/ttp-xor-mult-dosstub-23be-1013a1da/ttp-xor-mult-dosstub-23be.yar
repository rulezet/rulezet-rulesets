rule TTP_XOR_MULT_DOSStub_23be {
  strings:
    $key_23be = { 77 d6 [2] 03 ce [2] 44 cc [2] 03 dd [2] 4d d1 [2] 41 db [2] 56 d0 [2] 4d 9e [2] 70 }

  condition:
    any of them
}