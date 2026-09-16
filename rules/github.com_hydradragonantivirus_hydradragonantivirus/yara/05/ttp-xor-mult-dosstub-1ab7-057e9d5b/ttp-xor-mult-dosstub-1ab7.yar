rule TTP_XOR_MULT_DOSStub_1ab7 {
  strings:
    $key_1ab7 = { 4e df [2] 3a c7 [2] 7d c5 [2] 3a d4 [2] 74 d8 [2] 78 d2 [2] 6f d9 [2] 74 97 [2] 49 }

  condition:
    any of them
}