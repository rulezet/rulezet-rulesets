rule TTP_XOR_MULT_DOSStub_06be {
  strings:
    $key_06be = { 52 d6 [2] 26 ce [2] 61 cc [2] 26 dd [2] 68 d1 [2] 64 db [2] 73 d0 [2] 68 9e [2] 55 }

  condition:
    any of them
}