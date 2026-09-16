rule TTP_XOR_MULT_DOSStub_4ab7 {
  strings:
    $key_4ab7 = { 1e df [2] 6a c7 [2] 2d c5 [2] 6a d4 [2] 24 d8 [2] 28 d2 [2] 3f d9 [2] 24 97 [2] 19 }

  condition:
    any of them
}