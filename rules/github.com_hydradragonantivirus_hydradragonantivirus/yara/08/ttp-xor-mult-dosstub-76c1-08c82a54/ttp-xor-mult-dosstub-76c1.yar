rule TTP_XOR_MULT_DOSStub_76c1 {
  strings:
    $key_76c1 = { 22 a9 [2] 56 b1 [2] 11 b3 [2] 56 a2 [2] 18 ae [2] 14 a4 [2] 03 af [2] 18 e1 [2] 25 }

  condition:
    any of them
}