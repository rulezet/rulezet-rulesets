rule TTP_XOR_MULT_DOSStub_70f0 {
  strings:
    $key_70f0 = { 24 98 [2] 50 80 [2] 17 82 [2] 50 93 [2] 1e 9f [2] 12 95 [2] 05 9e [2] 1e d0 [2] 23 }

  condition:
    any of them
}