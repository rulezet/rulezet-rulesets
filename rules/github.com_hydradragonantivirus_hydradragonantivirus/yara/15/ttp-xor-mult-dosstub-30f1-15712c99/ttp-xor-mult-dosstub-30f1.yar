rule TTP_XOR_MULT_DOSStub_30f1 {
  strings:
    $key_30f1 = { 64 99 [2] 10 81 [2] 57 83 [2] 10 92 [2] 5e 9e [2] 52 94 [2] 45 9f [2] 5e d1 [2] 63 }

  condition:
    any of them
}