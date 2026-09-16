rule TTP_XOR_MULT_DOSStub_15be {
  strings:
    $key_15be = { 41 d6 [2] 35 ce [2] 72 cc [2] 35 dd [2] 7b d1 [2] 77 db [2] 60 d0 [2] 7b 9e [2] 46 }

  condition:
    any of them
}