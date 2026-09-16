rule TTP_XOR_MULT_DOSStub_58b7 {
  strings:
    $key_58b7 = { 0c df [2] 78 c7 [2] 3f c5 [2] 78 d4 [2] 36 d8 [2] 3a d2 [2] 2d d9 [2] 36 97 [2] 0b }

  condition:
    any of them
}