rule TTP_XOR_MULT_DOSStub_6cb7 {
  strings:
    $key_6cb7 = { 38 df [2] 4c c7 [2] 0b c5 [2] 4c d4 [2] 02 d8 [2] 0e d2 [2] 19 d9 [2] 02 97 [2] 3f }

  condition:
    any of them
}