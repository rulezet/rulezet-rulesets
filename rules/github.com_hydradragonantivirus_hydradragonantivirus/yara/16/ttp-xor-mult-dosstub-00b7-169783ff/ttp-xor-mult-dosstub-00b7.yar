rule TTP_XOR_MULT_DOSStub_00b7 {
  strings:
    $key_00b7 = { 54 df [2] 20 c7 [2] 67 c5 [2] 20 d4 [2] 6e d8 [2] 62 d2 [2] 75 d9 [2] 6e 97 [2] 53 }

  condition:
    any of them
}