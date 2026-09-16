rule TTP_XOR_MULT_DOSStub_1eb3 {
  strings:
    $key_1eb3 = { 4a db [2] 3e c3 [2] 79 c1 [2] 3e d0 [2] 70 dc [2] 7c d6 [2] 6b dd [2] 70 93 [2] 4d }

  condition:
    any of them
}