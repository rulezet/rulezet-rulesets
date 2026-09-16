rule TTP_XOR_MULT_DOSStub_7ab9 {
  strings:
    $key_7ab9 = { 2e d1 [2] 5a c9 [2] 1d cb [2] 5a da [2] 14 d6 [2] 18 dc [2] 0f d7 [2] 14 99 [2] 29 }

  condition:
    any of them
}