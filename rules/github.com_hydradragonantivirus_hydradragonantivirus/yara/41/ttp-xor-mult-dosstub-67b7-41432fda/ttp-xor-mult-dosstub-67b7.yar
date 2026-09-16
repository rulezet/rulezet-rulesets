rule TTP_XOR_MULT_DOSStub_67b7 {
  strings:
    $key_67b7 = { 33 df [2] 47 c7 [2] 00 c5 [2] 47 d4 [2] 09 d8 [2] 05 d2 [2] 12 d9 [2] 09 97 [2] 34 }

  condition:
    any of them
}