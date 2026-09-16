rule TTP_XOR_MULT_DOSStub_3eb7 {
  strings:
    $key_3eb7 = { 6a df [2] 1e c7 [2] 59 c5 [2] 1e d4 [2] 50 d8 [2] 5c d2 [2] 4b d9 [2] 50 97 [2] 6d }

  condition:
    any of them
}