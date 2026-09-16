rule TTP_XOR_MULT_DOSStub_2bbe {
  strings:
    $key_2bbe = { 7f d6 [2] 0b ce [2] 4c cc [2] 0b dd [2] 45 d1 [2] 49 db [2] 5e d0 [2] 45 9e [2] 78 }

  condition:
    any of them
}