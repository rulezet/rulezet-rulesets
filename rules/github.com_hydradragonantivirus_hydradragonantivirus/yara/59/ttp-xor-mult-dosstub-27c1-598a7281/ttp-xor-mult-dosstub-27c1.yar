rule TTP_XOR_MULT_DOSStub_27c1 {
  strings:
    $key_27c1 = { 73 a9 [2] 07 b1 [2] 40 b3 [2] 07 a2 [2] 49 ae [2] 45 a4 [2] 52 af [2] 49 e1 [2] 74 }

  condition:
    any of them
}