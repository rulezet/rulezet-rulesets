rule TTP_XOR_MULT_DOSStub_abbe {
  strings:
    $key_abbe = { ff d6 [2] 8b ce [2] cc cc [2] 8b dd [2] c5 d1 [2] c9 db [2] de d0 [2] c5 9e [2] f8 }

  condition:
    any of them
}