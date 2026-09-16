rule TTP_XOR_MULT_DOSStub_26c1 {
  strings:
    $key_26c1 = { 72 a9 [2] 06 b1 [2] 41 b3 [2] 06 a2 [2] 48 ae [2] 44 a4 [2] 53 af [2] 48 e1 [2] 75 }

  condition:
    any of them
}