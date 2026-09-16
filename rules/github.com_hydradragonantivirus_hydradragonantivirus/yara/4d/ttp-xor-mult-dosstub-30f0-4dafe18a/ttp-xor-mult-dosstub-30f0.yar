rule TTP_XOR_MULT_DOSStub_30f0 {
  strings:
    $key_30f0 = { 64 98 [2] 10 80 [2] 57 82 [2] 10 93 [2] 5e 9f [2] 52 95 [2] 45 9e [2] 5e d0 [2] 63 }

  condition:
    any of them
}