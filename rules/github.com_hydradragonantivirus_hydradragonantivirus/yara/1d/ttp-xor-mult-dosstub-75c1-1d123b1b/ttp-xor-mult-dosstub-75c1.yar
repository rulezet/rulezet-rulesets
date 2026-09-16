rule TTP_XOR_MULT_DOSStub_75c1 {
  strings:
    $key_75c1 = { 21 a9 [2] 55 b1 [2] 12 b3 [2] 55 a2 [2] 1b ae [2] 17 a4 [2] 00 af [2] 1b e1 [2] 26 }

  condition:
    any of them
}