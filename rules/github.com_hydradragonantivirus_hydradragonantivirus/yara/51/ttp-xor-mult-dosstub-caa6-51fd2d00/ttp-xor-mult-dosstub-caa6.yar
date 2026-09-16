rule TTP_XOR_MULT_DOSStub_caa6 {
  strings:
    $key_caa6 = { 9e ce [2] ea d6 [2] ad d4 [2] ea c5 [2] a4 c9 [2] a8 c3 [2] bf c8 [2] a4 86 [2] 99 }

  condition:
    any of them
}