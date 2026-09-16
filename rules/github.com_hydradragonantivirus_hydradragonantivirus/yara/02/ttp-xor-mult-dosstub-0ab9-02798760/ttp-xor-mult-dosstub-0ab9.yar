rule TTP_XOR_MULT_DOSStub_0ab9 {
  strings:
    $key_0ab9 = { 5e d1 [2] 2a c9 [2] 6d cb [2] 2a da [2] 64 d6 [2] 68 dc [2] 7f d7 [2] 64 99 [2] 59 }

  condition:
    any of them
}