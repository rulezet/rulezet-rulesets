rule TTP_XOR_MULT_DOSStub_31c1 {
  strings:
    $key_31c1 = { 65 a9 [2] 11 b1 [2] 56 b3 [2] 11 a2 [2] 5f ae [2] 53 a4 [2] 44 af [2] 5f e1 [2] 62 }

  condition:
    any of them
}