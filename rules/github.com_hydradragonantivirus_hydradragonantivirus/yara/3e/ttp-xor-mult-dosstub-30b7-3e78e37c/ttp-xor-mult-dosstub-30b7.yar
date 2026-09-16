rule TTP_XOR_MULT_DOSStub_30b7 {
  strings:
    $key_30b7 = { 64 df [2] 10 c7 [2] 57 c5 [2] 10 d4 [2] 5e d8 [2] 52 d2 [2] 45 d9 [2] 5e 97 [2] 63 }

  condition:
    any of them
}