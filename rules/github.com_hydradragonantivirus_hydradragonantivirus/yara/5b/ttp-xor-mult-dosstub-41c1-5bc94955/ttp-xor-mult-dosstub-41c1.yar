rule TTP_XOR_MULT_DOSStub_41c1 {
  strings:
    $key_41c1 = { 15 a9 [2] 61 b1 [2] 26 b3 [2] 61 a2 [2] 2f ae [2] 23 a4 [2] 34 af [2] 2f e1 [2] 12 }

  condition:
    any of them
}