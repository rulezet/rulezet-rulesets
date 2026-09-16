rule TTP_XOR_MULT_DOSStub_0fb7 {
  strings:
    $key_0fb7 = { 5b df [2] 2f c7 [2] 68 c5 [2] 2f d4 [2] 61 d8 [2] 6d d2 [2] 7a d9 [2] 61 97 [2] 5c }

  condition:
    any of them
}