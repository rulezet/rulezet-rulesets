rule TTP_XOR_MULT_DOSStub_19be {
  strings:
    $key_19be = { 4d d6 [2] 39 ce [2] 7e cc [2] 39 dd [2] 77 d1 [2] 7b db [2] 6c d0 [2] 77 9e [2] 4a }

  condition:
    any of them
}