rule TTP_XOR_MULT_DOSStub_15c1 {
  strings:
    $key_15c1 = { 41 a9 [2] 35 b1 [2] 72 b3 [2] 35 a2 [2] 7b ae [2] 77 a4 [2] 60 af [2] 7b e1 [2] 46 }

  condition:
    any of them
}