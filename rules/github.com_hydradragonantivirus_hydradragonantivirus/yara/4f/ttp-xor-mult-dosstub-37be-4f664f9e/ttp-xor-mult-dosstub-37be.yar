rule TTP_XOR_MULT_DOSStub_37be {
  strings:
    $key_37be = { 63 d6 [2] 17 ce [2] 50 cc [2] 17 dd [2] 59 d1 [2] 55 db [2] 42 d0 [2] 59 9e [2] 64 }

  condition:
    any of them
}