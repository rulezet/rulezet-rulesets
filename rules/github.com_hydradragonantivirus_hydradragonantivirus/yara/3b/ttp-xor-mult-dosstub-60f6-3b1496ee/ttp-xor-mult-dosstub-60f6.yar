rule TTP_XOR_MULT_DOSStub_60f6 {
  strings:
    $key_60f6 = { 34 9e [2] 40 86 [2] 07 84 [2] 40 95 [2] 0e 99 [2] 02 93 [2] 15 98 [2] 0e d6 [2] 33 }

  condition:
    any of them
}