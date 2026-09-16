rule TTP_XOR_MULT_DOSStub_0eb7 {
  strings:
    $key_0eb7 = { 5a df [2] 2e c7 [2] 69 c5 [2] 2e d4 [2] 60 d8 [2] 6c d2 [2] 7b d9 [2] 60 97 [2] 5d }

  condition:
    any of them
}