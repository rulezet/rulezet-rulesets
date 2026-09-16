rule TTP_XOR_MULT_DOSStub_40f7 {
  strings:
    $key_40f7 = { 14 9f [2] 60 87 [2] 27 85 [2] 60 94 [2] 2e 98 [2] 22 92 [2] 35 99 [2] 2e d7 [2] 13 }

  condition:
    any of them
}