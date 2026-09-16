rule TTP_XOR_MULT_DOSStub_35be {
  strings:
    $key_35be = { 61 d6 [2] 15 ce [2] 52 cc [2] 15 dd [2] 5b d1 [2] 57 db [2] 40 d0 [2] 5b 9e [2] 66 }

  condition:
    any of them
}