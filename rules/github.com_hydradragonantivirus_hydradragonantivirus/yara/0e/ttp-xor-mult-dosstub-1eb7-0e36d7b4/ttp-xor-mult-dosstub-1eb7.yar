rule TTP_XOR_MULT_DOSStub_1eb7 {
  strings:
    $key_1eb7 = { 4a df [2] 3e c7 [2] 79 c5 [2] 3e d4 [2] 70 d8 [2] 7c d2 [2] 6b d9 [2] 70 97 [2] 4d }

  condition:
    any of them
}