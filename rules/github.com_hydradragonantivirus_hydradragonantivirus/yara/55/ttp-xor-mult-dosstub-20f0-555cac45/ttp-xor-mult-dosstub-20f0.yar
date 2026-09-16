rule TTP_XOR_MULT_DOSStub_20f0 {
  strings:
    $key_20f0 = { 74 98 [2] 00 80 [2] 47 82 [2] 00 93 [2] 4e 9f [2] 42 95 [2] 55 9e [2] 4e d0 [2] 73 }

  condition:
    any of them
}