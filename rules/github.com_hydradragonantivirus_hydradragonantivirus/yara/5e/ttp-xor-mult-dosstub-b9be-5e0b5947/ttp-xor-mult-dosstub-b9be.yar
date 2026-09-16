rule TTP_XOR_MULT_DOSStub_b9be {
  strings:
    $key_b9be = { ed d6 [2] 99 ce [2] de cc [2] 99 dd [2] d7 d1 [2] db db [2] cc d0 [2] d7 9e [2] ea }

  condition:
    any of them
}