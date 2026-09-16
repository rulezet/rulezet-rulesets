rule TTP_XOR_MULT_DOSStub_e5c1 {
  strings:
    $key_e5c1 = { b1 a9 [2] c5 b1 [2] 82 b3 [2] c5 a2 [2] 8b ae [2] 87 a4 [2] 90 af [2] 8b e1 [2] b6 }

  condition:
    any of them
}