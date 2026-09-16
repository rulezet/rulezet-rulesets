rule TTP_XOR_MULT_DOSStub_10f7 {
  strings:
    $key_10f7 = { 44 9f [2] 30 87 [2] 77 85 [2] 30 94 [2] 7e 98 [2] 72 92 [2] 65 99 [2] 7e d7 [2] 43 }

  condition:
    any of them
}