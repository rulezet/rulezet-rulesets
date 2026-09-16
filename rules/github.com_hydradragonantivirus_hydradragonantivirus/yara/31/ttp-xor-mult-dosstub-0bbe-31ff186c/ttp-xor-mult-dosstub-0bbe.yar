rule TTP_XOR_MULT_DOSStub_0bbe {
  strings:
    $key_0bbe = { 5f d6 [2] 2b ce [2] 6c cc [2] 2b dd [2] 65 d1 [2] 69 db [2] 7e d0 [2] 65 9e [2] 58 }

  condition:
    any of them
}