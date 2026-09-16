rule TTP_XOR_MULT_DOSStub_41b7 {
  strings:
    $key_41b7 = { 15 df [2] 61 c7 [2] 26 c5 [2] 61 d4 [2] 2f d8 [2] 23 d2 [2] 34 d9 [2] 2f 97 [2] 12 }

  condition:
    any of them
}