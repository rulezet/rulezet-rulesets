rule TTP_XOR_MULT_DOSStub_45fa {
  strings:
    $key_45fa = { 11 92 [2] 65 8a [2] 22 88 [2] 65 99 [2] 2b 95 [2] 27 9f [2] 30 94 [2] 2b da [2] 16 }

  condition:
    any of them
}