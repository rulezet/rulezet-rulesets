rule TTP_XOR_MULT_DOSStub_54b7 {
  strings:
    $key_54b7 = { 00 df [2] 74 c7 [2] 33 c5 [2] 74 d4 [2] 3a d8 [2] 36 d2 [2] 21 d9 [2] 3a 97 [2] 07 }

  condition:
    any of them
}