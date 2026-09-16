rule TTP_XOR_MULT_DOSStub_10f1 {
  strings:
    $key_10f1 = { 44 99 [2] 30 81 [2] 77 83 [2] 30 92 [2] 7e 9e [2] 72 94 [2] 65 9f [2] 7e d1 [2] 43 }

  condition:
    any of them
}