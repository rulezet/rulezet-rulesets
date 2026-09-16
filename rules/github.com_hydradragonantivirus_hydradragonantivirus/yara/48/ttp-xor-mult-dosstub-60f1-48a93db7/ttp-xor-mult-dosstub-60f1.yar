rule TTP_XOR_MULT_DOSStub_60f1 {
  strings:
    $key_60f1 = { 34 99 [2] 40 81 [2] 07 83 [2] 40 92 [2] 0e 9e [2] 02 94 [2] 15 9f [2] 0e d1 [2] 33 }

  condition:
    any of them
}