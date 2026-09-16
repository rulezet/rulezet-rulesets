rule TTP_XOR_MULT_DOSStub_40f0 {
  strings:
    $key_40f0 = { 14 98 [2] 60 80 [2] 27 82 [2] 60 93 [2] 2e 9f [2] 22 95 [2] 35 9e [2] 2e d0 [2] 13 }

  condition:
    any of them
}