rule TTP_XOR_MULT_DOSStub_17b7 {
  strings:
    $key_17b7 = { 43 df [2] 37 c7 [2] 70 c5 [2] 37 d4 [2] 79 d8 [2] 75 d2 [2] 62 d9 [2] 79 97 [2] 44 }

  condition:
    any of them
}