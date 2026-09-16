rule TTP_XOR_MULT_DOSStub_7bbe {
  strings:
    $key_7bbe = { 2f d6 [2] 5b ce [2] 1c cc [2] 5b dd [2] 15 d1 [2] 19 db [2] 0e d0 [2] 15 9e [2] 28 }

  condition:
    any of them
}