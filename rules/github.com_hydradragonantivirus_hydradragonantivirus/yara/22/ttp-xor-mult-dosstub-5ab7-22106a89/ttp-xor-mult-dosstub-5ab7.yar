rule TTP_XOR_MULT_DOSStub_5ab7 {
  strings:
    $key_5ab7 = { 0e df [2] 7a c7 [2] 3d c5 [2] 7a d4 [2] 34 d8 [2] 38 d2 [2] 2f d9 [2] 34 97 [2] 09 }

  condition:
    any of them
}