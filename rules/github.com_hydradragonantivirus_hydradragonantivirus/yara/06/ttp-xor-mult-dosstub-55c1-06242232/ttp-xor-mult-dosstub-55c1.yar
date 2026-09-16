rule TTP_XOR_MULT_DOSStub_55c1 {
  strings:
    $key_55c1 = { 01 a9 [2] 75 b1 [2] 32 b3 [2] 75 a2 [2] 3b ae [2] 37 a4 [2] 20 af [2] 3b e1 [2] 06 }

  condition:
    any of them
}