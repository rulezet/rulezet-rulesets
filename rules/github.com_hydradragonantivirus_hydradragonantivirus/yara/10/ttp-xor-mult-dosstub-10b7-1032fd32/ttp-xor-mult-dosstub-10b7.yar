rule TTP_XOR_MULT_DOSStub_10b7 {
  strings:
    $key_10b7 = { 44 df [2] 30 c7 [2] 77 c5 [2] 30 d4 [2] 7e d8 [2] 72 d2 [2] 65 d9 [2] 7e 97 [2] 43 }

  condition:
    any of them
}