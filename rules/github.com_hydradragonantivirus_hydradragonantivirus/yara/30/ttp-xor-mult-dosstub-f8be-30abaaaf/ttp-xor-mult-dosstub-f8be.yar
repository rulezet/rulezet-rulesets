rule TTP_XOR_MULT_DOSStub_f8be {
  strings:
    $key_f8be = { ac d6 [2] d8 ce [2] 9f cc [2] d8 dd [2] 96 d1 [2] 9a db [2] 8d d0 [2] 96 9e [2] ab }

  condition:
    any of them
}