rule TTP_XOR_MULT_DOSStub_56c1 {
  strings:
    $key_56c1 = { 02 a9 [2] 76 b1 [2] 31 b3 [2] 76 a2 [2] 38 ae [2] 34 a4 [2] 23 af [2] 38 e1 [2] 05 }

  condition:
    any of them
}