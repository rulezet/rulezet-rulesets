rule TTP_XOR_MULT_DOSStub_02be {
  strings:
    $key_02be = { 56 d6 [2] 22 ce [2] 65 cc [2] 22 dd [2] 6c d1 [2] 60 db [2] 77 d0 [2] 6c 9e [2] 51 }

  condition:
    any of them
}