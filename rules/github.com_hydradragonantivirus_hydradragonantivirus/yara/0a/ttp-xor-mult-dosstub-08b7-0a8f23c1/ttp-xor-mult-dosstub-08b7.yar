rule TTP_XOR_MULT_DOSStub_08b7 {
  strings:
    $key_08b7 = { 5c df [2] 28 c7 [2] 6f c5 [2] 28 d4 [2] 66 d8 [2] 6a d2 [2] 7d d9 [2] 66 97 [2] 5b }

  condition:
    any of them
}