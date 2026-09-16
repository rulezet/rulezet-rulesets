rule TTP_XOR_MULT_DOSStub_54c1 {
  strings:
    $key_54c1 = { 00 a9 [2] 74 b1 [2] 33 b3 [2] 74 a2 [2] 3a ae [2] 36 a4 [2] 21 af [2] 3a e1 [2] 07 }

  condition:
    any of them
}