rule TTP_XOR_MULT_DOSStub_39b7 {
  strings:
    $key_39b7 = { 6d df [2] 19 c7 [2] 5e c5 [2] 19 d4 [2] 57 d8 [2] 5b d2 [2] 4c d9 [2] 57 97 [2] 6a }

  condition:
    any of them
}