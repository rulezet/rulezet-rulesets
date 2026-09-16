rule TTP_XOR_MULT_DOSStub_50b7 {
  strings:
    $key_50b7 = { 04 df [2] 70 c7 [2] 37 c5 [2] 70 d4 [2] 3e d8 [2] 32 d2 [2] 25 d9 [2] 3e 97 [2] 03 }

  condition:
    any of them
}