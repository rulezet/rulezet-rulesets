rule TTP_XOR_MULT_DOSStub_55fa {
  strings:
    $key_55fa = { 01 92 [2] 75 8a [2] 32 88 [2] 75 99 [2] 3b 95 [2] 37 9f [2] 20 94 [2] 3b da [2] 06 }

  condition:
    any of them
}