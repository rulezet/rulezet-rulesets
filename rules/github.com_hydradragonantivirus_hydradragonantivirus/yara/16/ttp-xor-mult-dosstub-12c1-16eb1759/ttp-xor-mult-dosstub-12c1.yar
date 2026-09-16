rule TTP_XOR_MULT_DOSStub_12c1 {
  strings:
    $key_12c1 = { 46 a9 [2] 32 b1 [2] 75 b3 [2] 32 a2 [2] 7c ae [2] 70 a4 [2] 67 af [2] 7c e1 [2] 41 }

  condition:
    any of them
}