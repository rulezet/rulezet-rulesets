rule TTP_XOR_MULT_DOSStub_5eb7 {
  strings:
    $key_5eb7 = { 0a df [2] 7e c7 [2] 39 c5 [2] 7e d4 [2] 30 d8 [2] 3c d2 [2] 2b d9 [2] 30 97 [2] 0d }

  condition:
    any of them
}