rule TTP_XOR_MULT_DOSStub_4fb7 {
  strings:
    $key_4fb7 = { 1b df [2] 6f c7 [2] 28 c5 [2] 6f d4 [2] 21 d8 [2] 2d d2 [2] 3a d9 [2] 21 97 [2] 1c }

  condition:
    any of them
}