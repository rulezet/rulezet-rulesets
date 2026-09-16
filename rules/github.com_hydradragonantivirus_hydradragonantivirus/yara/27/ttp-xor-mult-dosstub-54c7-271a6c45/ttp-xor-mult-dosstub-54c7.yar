rule TTP_XOR_MULT_DOSStub_54c7 {
  strings:
    $key_54c7 = { 00 af [2] 74 b7 [2] 33 b5 [2] 74 a4 [2] 3a a8 [2] 36 a2 [2] 21 a9 [2] 3a e7 [2] 07 }

  condition:
    any of them
}