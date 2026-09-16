rule TTP_XOR_MULT_DOSStub_68b7 {
  strings:
    $key_68b7 = { 3c df [2] 48 c7 [2] 0f c5 [2] 48 d4 [2] 06 d8 [2] 0a d2 [2] 1d d9 [2] 06 97 [2] 3b }

  condition:
    any of them
}