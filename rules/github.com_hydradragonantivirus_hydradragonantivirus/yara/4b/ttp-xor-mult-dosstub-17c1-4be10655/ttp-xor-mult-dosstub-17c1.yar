rule TTP_XOR_MULT_DOSStub_17c1 {
  strings:
    $key_17c1 = { 43 a9 [2] 37 b1 [2] 70 b3 [2] 37 a2 [2] 79 ae [2] 75 a4 [2] 62 af [2] 79 e1 [2] 44 }

  condition:
    any of them
}