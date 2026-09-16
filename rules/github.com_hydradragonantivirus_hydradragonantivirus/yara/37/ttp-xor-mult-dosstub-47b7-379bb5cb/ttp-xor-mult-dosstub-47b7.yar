rule TTP_XOR_MULT_DOSStub_47b7 {
  strings:
    $key_47b7 = { 13 df [2] 67 c7 [2] 20 c5 [2] 67 d4 [2] 29 d8 [2] 25 d2 [2] 32 d9 [2] 29 97 [2] 14 }

  condition:
    any of them
}