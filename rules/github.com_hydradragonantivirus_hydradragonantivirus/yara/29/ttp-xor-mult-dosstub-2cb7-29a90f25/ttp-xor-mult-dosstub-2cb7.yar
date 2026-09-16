rule TTP_XOR_MULT_DOSStub_2cb7 {
  strings:
    $key_2cb7 = { 78 df [2] 0c c7 [2] 4b c5 [2] 0c d4 [2] 42 d8 [2] 4e d2 [2] 59 d9 [2] 42 97 [2] 7f }

  condition:
    any of them
}