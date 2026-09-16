rule TTP_XOR_MULT_DOSStub_30f6 {
  strings:
    $key_30f6 = { 64 9e [2] 10 86 [2] 57 84 [2] 10 95 [2] 5e 99 [2] 52 93 [2] 45 98 [2] 5e d6 [2] 63 }

  condition:
    any of them
}