rule TTP_XOR_MULT_DOSStub_f3be {
  strings:
    $key_f3be = { a7 d6 [2] d3 ce [2] 94 cc [2] d3 dd [2] 9d d1 [2] 91 db [2] 86 d0 [2] 9d 9e [2] a0 }

  condition:
    any of them
}