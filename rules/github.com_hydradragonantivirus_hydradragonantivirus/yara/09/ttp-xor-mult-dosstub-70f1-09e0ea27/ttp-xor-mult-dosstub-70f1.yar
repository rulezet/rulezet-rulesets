rule TTP_XOR_MULT_DOSStub_70f1 {
  strings:
    $key_70f1 = { 24 99 [2] 50 81 [2] 17 83 [2] 50 92 [2] 1e 9e [2] 12 94 [2] 05 9f [2] 1e d1 [2] 23 }

  condition:
    any of them
}