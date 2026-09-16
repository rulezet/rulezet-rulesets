rule TTP_XOR_MULT_DOSStub_70f6 {
  strings:
    $key_70f6 = { 24 9e [2] 50 86 [2] 17 84 [2] 50 95 [2] 1e 99 [2] 12 93 [2] 05 98 [2] 1e d6 [2] 23 }

  condition:
    any of them
}