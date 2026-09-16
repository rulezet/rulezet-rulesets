rule TTP_XOR_MULT_DOSStub_50f7 {
  strings:
    $key_50f7 = { 04 9f [2] 70 87 [2] 37 85 [2] 70 94 [2] 3e 98 [2] 32 92 [2] 25 99 [2] 3e d7 [2] 03 }

  condition:
    any of them
}