rule TTP_XOR_MULT_DOSStub_4eb7 {
  strings:
    $key_4eb7 = { 1a df [2] 6e c7 [2] 29 c5 [2] 6e d4 [2] 20 d8 [2] 2c d2 [2] 3b d9 [2] 20 97 [2] 1d }

  condition:
    any of them
}