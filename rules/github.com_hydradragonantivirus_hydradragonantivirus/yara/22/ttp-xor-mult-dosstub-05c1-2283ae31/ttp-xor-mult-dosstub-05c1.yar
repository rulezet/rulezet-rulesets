rule TTP_XOR_MULT_DOSStub_05c1 {
  strings:
    $key_05c1 = { 51 a9 [2] 25 b1 [2] 62 b3 [2] 25 a2 [2] 6b ae [2] 67 a4 [2] 70 af [2] 6b e1 [2] 56 }

  condition:
    any of them
}