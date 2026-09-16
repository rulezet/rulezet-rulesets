rule TTP_XOR_MULT_DOSStub_bbbe {
  strings:
    $key_bbbe = { ef d6 [2] 9b ce [2] dc cc [2] 9b dd [2] d5 d1 [2] d9 db [2] ce d0 [2] d5 9e [2] e8 }

  condition:
    any of them
}