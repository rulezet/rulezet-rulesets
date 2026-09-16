rule TTP_XOR_MULT_DOSStub_77b7 {
  strings:
    $key_77b7 = { 23 df [2] 57 c7 [2] 10 c5 [2] 57 d4 [2] 19 d8 [2] 15 d2 [2] 02 d9 [2] 19 97 [2] 24 }

  condition:
    any of them
}