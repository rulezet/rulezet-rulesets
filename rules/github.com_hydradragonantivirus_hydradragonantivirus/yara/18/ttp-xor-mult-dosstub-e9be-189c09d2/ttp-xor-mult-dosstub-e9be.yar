rule TTP_XOR_MULT_DOSStub_e9be {
  strings:
    $key_e9be = { bd d6 [2] c9 ce [2] 8e cc [2] c9 dd [2] 87 d1 [2] 8b db [2] 9c d0 [2] 87 9e [2] ba }

  condition:
    any of them
}