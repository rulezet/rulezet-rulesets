rule TTP_XOR_MULT_DOSStub_a9be {
  strings:
    $key_a9be = { fd d6 [2] 89 ce [2] ce cc [2] 89 dd [2] c7 d1 [2] cb db [2] dc d0 [2] c7 9e [2] fa }

  condition:
    any of them
}