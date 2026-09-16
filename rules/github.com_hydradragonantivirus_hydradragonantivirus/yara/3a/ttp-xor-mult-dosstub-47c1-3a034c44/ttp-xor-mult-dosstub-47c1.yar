rule TTP_XOR_MULT_DOSStub_47c1 {
  strings:
    $key_47c1 = { 13 a9 [2] 67 b1 [2] 20 b3 [2] 67 a2 [2] 29 ae [2] 25 a4 [2] 32 af [2] 29 e1 [2] 14 }

  condition:
    any of them
}