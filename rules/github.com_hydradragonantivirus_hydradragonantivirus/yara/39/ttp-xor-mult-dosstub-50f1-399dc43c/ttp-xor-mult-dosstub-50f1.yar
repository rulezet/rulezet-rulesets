rule TTP_XOR_MULT_DOSStub_50f1 {
  strings:
    $key_50f1 = { 04 99 [2] 70 81 [2] 37 83 [2] 70 92 [2] 3e 9e [2] 32 94 [2] 25 9f [2] 3e d1 [2] 03 }

  condition:
    any of them
}